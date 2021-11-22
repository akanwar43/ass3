import sys
from ParseUpdates import ParseUpdates
from RoutingTable import RoutingTable
from DetectHijacks import DetectHijacks
import logging
import argparse
if sys.version_info[0] >= 3:
    unicode = str

class Tests:
    def __init__(self):
        self.pu = ParseUpdates(filename="./data/updates.20080219.0015.bz2")
        self.rt = RoutingTable()
        self.dh = None
        self.cp_test_map = [self.__test_parser_full_cp1, self.__test_routing_applying_updates_cp2,
                            self.__test_routing_measuring_reachability_cp3, self.__test_routing_collapsing_table_cp4,
                            self.__test_routing_find_path_cp5, self.__test_hijacks_safe_updating_cp6]

    def run_checkpoint(self, checkpoint=1):
        logging.info("[CP%d] Executing tests for checkpoint %d." % (checkpoint, checkpoint))
        self.cp_test_map[checkpoint-1]()
        logging.info("[CP%d] Tests for checkpoint %d complete. Verify that your results match the "
                     "sample output log file." % (checkpoint, checkpoint))
        return

    def __test_parser_full_cp1(self):
        self.pu.parse_updates()
        logging.info("[CP1] Time taken to parse all records: %d second(s)" % self.pu.time_to_parse)
        logging.info("[CP1] Routes announced: %d | Routes withdrawn: %d" % (self.pu.n_announcements,
                                                                            self.pu.n_withdrawals))
        updates = self.pu.get_next_updates()
        while True:
            next_updates = updates.__next__()
            if next_updates['timestamp'] is None:
                logging.info("[CP1] No more updates to process in file: %s" % self.pu.filename)
                break
            else:
                logging.info("[CP1] At timestamp: %d | %d announcements | %d withdrawals" % (next_updates['timestamp'],
                                                                                             len(next_updates[
                                                                                                     'announcements']),
                                                                                             len(next_updates[
                                                                                                     'withdrawals'])))
        return

    def __test_routing_applying_updates_cp2(self):
        self.pu.parse_updates()
        updates = self.pu.get_next_updates()
        while True:
            next_updates = updates.__next__()
            if next_updates['timestamp'] is None:
                logging.info("[CP2] No more updates to process in file: %s" % self.pu.filename)
                break
            else:
                for announcement in next_updates["announcements"]:
                    self.rt.apply_announcement(announcement)
                for withdrawal in next_updates["withdrawals"]:
                    self.rt.apply_withdrawal(withdrawal)
        self.rt.helper_print_routing_table_descriptions(collapse=False)
        return

    def __test_routing_measuring_reachability_cp3(self):
        self.__test_routing_applying_updates_cp2()
        self.rt.measure_reachability()
        self.rt.helper_print_routing_table_descriptions(collapse=False)
        return

    def __test_routing_collapsing_table_cp4(self):
        self.__test_routing_measuring_reachability_cp3()
        self.rt.helper_print_routing_table_descriptions(collapse=True)
        return

    def __test_routing_find_path_cp5(self):
        self.__test_routing_collapsing_table_cp4()
        self.rt.find_path_to_destination(unicode("8.8.8.8"))
        self.rt.find_path_to_destination(unicode("125.161.0.1"))
        return

    def __test_hijacks_safe_updating_cp6(self):
        self.dh = DetectHijacks(start_table=self.rt, monitored_range='208.65.153.0/21')
        self.__test_routing_find_path_cp5()
        files = ["./data/updates.20080222.0208.bz2", "./data/updates.20080224.1839.bz2",
                 "./data/updates.20080224.2009.bz2", "./data/updates.20080224.2026.bz2",
                 "./data/updates.20080224.2041.bz2", "./data/updates.20080224.2056.bz2"]
        self.dh.update_routing_table_safely(files)
        self.dh.routing_table.helper_print_routing_table_descriptions()
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--checkpoint', '-cp', help="All code until the checkpoint ID will be executed.")
    parsed_args = parser.parse_args()
    if parsed_args.checkpoint is None:
        parser.print_help()
        sys.exit(0)
    t = Tests()
    t.run_checkpoint(checkpoint=int(parsed_args.checkpoint))


if __name__ == '__main__':
    main()