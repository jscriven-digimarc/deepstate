#!/usr/bin/env python3.6

import os
import logging
import argparse
import tarfile
import shutil

from typing import List, Dict, Optional

from deepstate.core import FuzzerFrontend, FuzzFrontendError

L = logging.getLogger(__name__)

class AFL_Ensemble(FuzzerFrontend):
  """ Defines AFL fuzzer frontend for Ensemble Fuzzing """

  NAME = "AFL-Ensemble"
  EXECUTABLES = {"FUZZER": "afl-fuzz",
                  "COMPILER": "afl-clang++"
                  }

  REQUIRE_SEEDS = True

  # below are required by fuzz.py, but we don't use them... they get overwritten later.
  PUSH_DIR = os.path.join("sync_dir", "queue")
  PULL_DIR = os.path.join("the_fuzzer", "queue")
  CRASH_DIR = os.path.join("the_fuzzer", "crashes")

  @classmethod
  def parse_args(cls) -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
      description=f"Use AFL as a backend for DeepState ensemble")

    parser.add_argument("--fuzzer_node_id", type=str, default="0", help="String with unique fuzzer node id.")
    parser.add_argument("--fuzzer_id", type=str, default="0", help="String with unique fuzzer id.")
    parser.add_argument("--ensemble_mode", type=str, default="SecondaryOnly", help="Parallel model for afl fuzzers: SecondaryOnly or MasterSecondary.")

    cls.parser = parser
    super(AFL_Ensemble, cls).parse_args()


  def compile(self) -> None: # type: ignore
    raise FuzzFrontendError("Compile no supported for AFL ensemble")

  def pre_exec(self):
    """
    Perform argparse and environment-related sanity checks.
    """
    # check for afl-qemu-trace if in QEMU mode 
    if 'Q' in self.fuzzer_args or self.blackbox == True:
      self.EXECUTABLES["AFL-QEMU-TRACE"] = "afl-qemu-trace"

    # only the primary fuzzer will return status and perform sync_cycle
    if self.fuzzer_id == '0':
      self.is_primary_fuzzer = True
    else:
      self.is_primary_fuzzer = False

    self.fuzzer_name = "fuzzer_" + self.fuzzer_node_id + "_" + self.fuzzer_id
    self.queue_dir = os.path.join(self.output_test_dir, self.fuzzer_name, "queue")
    self.crash_dir = os.path.join(self.output_test_dir, self.fuzzer_name, "crashes")
    self.hang_dir = os.path.join(self.output_test_dir, self.fuzzer_name, "hangs")

    # pull any new seeds
    if self.is_primary_fuzzer:
      new_seed_remote = os.path.join(self.sync_dir, "new_seeds")
      L.debug(f"{self.fuzzer_name}: Checking for new seeds in: {new_seed_remote}")

      # Create the local new seed dir and queue if they don't exist
      new_seed_dir = os.path.join(self.output_test_dir, "new_seeds")
      new_seed_queue = os.path.join(self.output_test_dir, "new_seeds", "queue")

      if not os.path.isdir(new_seed_dir):
        os.mkdir(new_seed_dir)
      if not os.path.isdir(new_seed_queue):
        os.mkdir(new_seed_queue)
 
      for f in os.listdir(new_seed_remote):
        L.debug(f"Found {f} new seed to pull into new local queue")
        try:
          shutil.move(os.path.join(new_seed_remote, f), new_seed_queue)
        except:
          L.warning("Seed not synched; likely pulled by another fuzzer")

    # Originally set in parent class, pre_exec will create these files
    self.stats_file: str = "deepstate-stats-" + self.fuzzer_id + ".txt"
    self.output_file: str = "fuzzer-output-" + self.fuzzer_id + ".txt"

    super().pre_exec()

    # check if core dump pattern is set as `core`
    if os.path.isfile("/proc/sys/kernel/core_pattern"):
      with open("/proc/sys/kernel/core_pattern") as f:
        if not "core" in f.read():
          raise FuzzFrontendError("No core dump pattern set. Execute 'echo core | sudo tee /proc/sys/kernel/core_pattern'")

    # resume fuzzing
    if len(os.listdir(self.output_test_dir)) > 1:
      #self.check_required_directories([self.push_dir, self.pull_dir, self.crash_dir])
      self.input_seeds = '-'
      L.info(f"Resuming fuzzing using seeds from {self.pull_dir} (skipping --input_seeds option).")
    else:
      raise FuzzFrontendError("Only resume fuzzing is suppored with ensembler...")


  @property
  def cmd(self):
    cmd_list: List[str] = list()

    #reset crash_dir (parent overrided this)
    self.crash_dir = os.path.join(self.output_test_dir, self.fuzzer_name, "crashes") 
    
    L.info(f"ALF Ensemble Fuzzer: {self.fuzzer_name} with parallel model: {self.ensemble_mode}")

    # guaranteed arguments
    cmd_list.extend(["-o", self.output_test_dir])

    if self.fuzzer_name == 'fuzzer_0_0' and self.ensemble_mode == 'MasterSecondary':
      L.info("Starting a Master fuzzer")
      cmd_list.extend(["-M", self.fuzzer_name])   # Spin up a 'master' fuzzer
    else:
      L.info("Starting a Secondary fuzzer")
      cmd_list.extend(["-S", self.fuzzer_name])   # Spin up a 'secondary' fuzzer
        
    if self.mem_limit == 0:
      cmd_list.extend(["-m", "1099511627776"])  # use 1TiB as unlimited
    else:
      cmd_list.extend(["-m", str(self.mem_limit)])

    for key, val in self.fuzzer_args:
      if len(key) == 1:
        cmd_list.append('-{}'.format(key))
      else:
        cmd_list.append('--{}'.format(key))
      if val is not None:
        cmd_list.append(val)

    # QEMU mode
    if self.blackbox == True:
      cmd_list.append('-Q')

    # optional arguments:
    # required, if provided: not auto-create and require any file inside
    if self.input_seeds:
      cmd_list.extend(["-i", self.input_seeds])

    if self.exec_timeout:
      cmd_list.extend(["-t", str(self.exec_timeout)])

    if self.dictionary:
      cmd_list.extend(["-x", self.dictionary])

    return self.build_cmd(cmd_list)


  def populate_stats(self):
    """
    Retrieves and parses the stats file produced by AFL
    """
    stat_file_path: str = os.path.join(self.output_test_dir, self.fuzzer_name, "fuzzer_stats")
    lines = open(stat_file_path, "r").readlines()
    for line in lines:
      key = line.split(":", 1)[0].strip()
      value = line.split(":", 1)[1].strip()
      if key in self.stats:
        self.stats[key] = value
    super().populate_stats()

  def reporter(self) -> Dict[str, Optional[str]]:
    """
    Report a summarized version of statistics, ideal for ensembler output.
    """
    self.populate_stats()
    return dict({
        "Execs Done": self.stats["execs_done"],
        "Cycle Completed": self.stats["cycles_done"],
        "Unique Crashes": self.stats["unique_crashes"],
        "Unique Hangs": self.stats["unique_hangs"],
    })


  def _sync_seeds(self, src, dest, excludes=[]) -> None:
    L.info("Seed Sync not implemented in AFL Ensembler")
    #super()._sync_seeds(src, dest, excludes=excludes)


  def post_exec(self) -> None:
    super().post_exec()

  def ensemble(self, local_queue: Optional[str] = None, global_queue: Optional[str] = None):
    L.info("Calling AFL ensemble")
   
    # All fuzzers push their hangs and crashes
    L.debug(f"{self.fuzzer_name}: Pushing any hangs...")
    remote_hangs = os.path.join(self.sync_dir, "hangs")
    for path, directories, files in os.walk(self.hang_dir):
      for f in files:
        hangfile = os.path.join(self.hang_dir, f)
        shutil.copy2(hangfile, remote_hangs)

    L.debug(f"{self.fuzzer_name}: Pushing any crashes...")
    remote_crashes = os.path.join(self.sync_dir, "crashes")
    for path, directories, files in os.walk(self.crash_dir):
      for f in files:
        crashfile = os.path.join(self.crash_dir, f)
        shutil.copy2(crashfile, remote_crashes)
 
    # Only the primary fuzzer will sync!
    if self.is_primary_fuzzer:
      L.info(f"{self.fuzzer_name}: Pushing my Queue/s...")
      # tgz up the current queue and copy over
      tar = tarfile.open("fuzzer_tmp.tgz", "w:gz")
     
      # there is no exception handler around this because if we cannot
      # for whatever reason tar up and push our queue, something is wrong! 
      for d in os.listdir(self.output_test_dir):
        if d.startswith(self.fuzzer_name[:8],0,8):
          L.debug("Adding dir to archive: " + d)
          infofile = os.path.join(d, "fuzzer_stats")
          queuedir = os.path.join(d, "queue")
          
          fullinfopath = os.path.join(self.output_test_dir, infofile)
          fullqueuedir =  os.path.join(self.output_test_dir, queuedir)
          tar.add(fullinfopath, arcname=infofile)
          tar.add(fullqueuedir, arcname=queuedir)

      tar.close()

      remote_archive = os.path.join(self.sync_dir, "FuzzData_" + self.fuzzer_node_id + ".tgz")
      shutil.move("fuzzer_tmp.tgz", remote_archive)

      L.info(f"{self.fuzzer_name}: Pulling all remote queues...")
      for f in os.listdir(self.sync_dir):
        # do not re-sync the tgz we sent up, pull everyone else's though
        if f.endswith(".tgz") and not f.startswith("FuzzData_" + self.fuzzer_node_id):
          L.debug(f"Copy and Extract: {f} to {self.output_test_dir}")
          try:
            shutil.copy2(os.path.join(self.sync_dir,f), "fuzzer_tmp.tgz")
            tar = tarfile.open("fuzzer_tmp.tgz", 'r:gz')
            tar.extractall(path=self.output_test_dir)
            tar.close()
            os.remove("fuzzer_tmp.tgz")
          except:
            # if something goes wrong, just try again next loop through, log a message and move on
            # worst case is we have a lingering fuzzer_tmp.tgz, but it will be overridden next cycle anyway.
            L.warning(f"Something went wrong pulling queue: {f}, retry on next sync cycle...")

      L.debug("Queue sync complete")
    else:
      L.info(f"{self.fuzzer_name}: Skipping queue management ensemble step, this is not the primary fuzzer")

def main():
  fuzzer = AFL_Ensemble(envvar="AFL_HOME")
  return fuzzer.main()


if __name__ == "__main__":
  exit(main())
