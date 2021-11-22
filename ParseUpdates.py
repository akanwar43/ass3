"""
CS3640 | Fall 2021 | Assignment 3
BGP Routing Tables and Identifying BGP Hijacks
ParseUpdates.py
---------------
The class in this file contains methods to parse BGP MRT files that contain
route announcements and withdrawals from peer ASes. You will need to
implement methods to read a supplied MRT file and extract specific information
about announced and withdrawn routes. You will then use this information to
build your routing table.
"""

import ipaddress
import mrtparse
import json
import time
import logging


class ParseUpdates:
    """
        Class for parsing updates recorded in BGP MRT dumps.
    """
    def __init__(self, filename):
        """
        :param filename: This is the MRT file to be parsed by the methods in
        this class. Sample files can be found in `./data/`.
        self.announcements and self.withdrawals are dictionaries that are keyed
        by timestamps and contain the list of all BGP route announcements and
        withdrawals at each timestamp.
        self.n_announcements and self.n_withdrawals are the number of route
        announcements and withdrawals observed in the supplied MRT file.
        You will update all these parameters as you complete checkpoints 1 & 2.
        """
        self.filename = filename
        self.announcements = {
        }
        self.withdrawals = {
        }
        self.n_announcements, self.n_withdrawals = 0, 0
        self.time_to_parse = 0


    def parse_updates(self):
        """
        Checkpoint ID: 1 [1 point]
        In this function, you will read an MRT file using the `mrtparse` library.
        For each update in the MRT file, you will need to parse the timestamp,
        the peer_as that shared the update, and the bgp message containing the
        updates. You will then call the `__parse_announcement_updates` and
        `__parse_withdrawal_updates` methods with these parameters.
        :return: True if parsing was completed successfully. False otherwise.
        """
            
        start_time = time.time()

        for entry in mrtparse.Reader(self.filename):
            entry_data = entry.data
            entry_timestamp = entry_data['timestamp']
            entry_source_peer = entry_data['peer_as']
            entry_bgpMessage = entry_data['bgp_message']
            self.__parse_announcement_updates(entry_timestamp, entry_source_peer, entry_bgpMessage)
            self.__parse_withdrawal_updates(entry_timestamp, entry_source_peer, entry_bgpMessage)

        #for item in entry_bgpMessage['path_attributes']:
        #    for node in item:
        #        print(node)

        self.time_to_parse = time.time() - start_time
        logging.info("Time taken to parse all records: %d second(s)" % self.time_to_parse)
        logging.info("Routes announced: %d | Routes withdrawn: %d" % (self.n_announcements, self.n_withdrawals))
        return True

    def __parse_announcement_updates(self, timestamp, peer_as, bgp_message):
        """
        Checkpoint ID: 1 [1 points]
        In this function, you will take a timestamp, peer_as, and bgp_message as
        input and then do the following:
            - increment n_announcements by the number of announced routes contained
                in bgp_message.
            - extract the advertised destination ip ranges from bgp_message.
            - extract the advertised AS path and next hop information from the bgp
                attributes in bgp_message.
            - create a dictionary named `update` which has the following keys
                populated by the data you just extracted: timestamp, range (this
                is the advertised CIDR IP address range being announced), next_hop,
                peer_as, and as_path.
            - update the `self.announcements` attribute with this new record.
                `self.announcements` is a dictionary of lists keyed by `timestamp`.
                There will be multiple messages for a single timestamp, so
                make sure that you aren't overwriting any existing entries
                when you should be appending to the already existing entries
                instead.
        :param timestamp: Timestamp obtained from the BGP header.
        :param peer_as: Peer AS obtained from the BGP header.
        :param bgp_message: BGP message containing all updates.
        :return: True if announcements were properly recorded. False otherwise.
        """
        ###        
        update = {}
        CIDR = []
        as_path_data = []
        next_hop_data = []

        message_packet  = bgp_message['path_attributes']
        nlri = bgp_message['nlri']
        if nlri != []:
            for item in message_packet:
                if item['type'][1] == 'AS_PATH':
                    as_path_data.append(item['value'])
                if item['type'][1] == 'NEXT_HOP':
                    next_hop_data.append(item['value'])

            for item in nlri:
                update = {
                'timestamp' : timestamp,
                'range' : item,
                'next_hop' : next_hop_data,
                'peer_as' : peer_as,
                'as_path' : as_path_data
            }
                time = timestamp[0]
                if time not in self.announcements:
                    self.announcements.update( {time : []})
                    self.announcements[time].append(update)

                else:
                    self.announcements[time].append(update)
                self.n_announcements = self.n_announcements + 1


        return True

    def __parse_withdrawal_updates(self, timestamp, peer_as, bgp_message):
        """
        Checkpoint ID: 1 [1 points]
        In this function, you will take a timestamp, peer_as, and bgp_message as
        input and then do the following:
            - increment n_withdrawals by the number of withdrawn routes contained
                in bgp_message.
            - create a dictionary named `update` which has the following keys
                populated by the data you just extracted: timestamp, range (this
                is the advertised CIDR IP address range being announced),
                peer_as, and as_path.
            - update the `self.withdrawals` attribute with this new record.
                `self.withdrawals` is a dictionary of lists keyed by `timestamp`.
                There will be multiple messages for a single timestamp, so
                make sure that you aren't overwriting any existing entries
                when you should be appending to the already existing entries
                instead.
        :param timestamp: Timestamp obtained from the BGP header.
        :param peer_as: Peer AS obtained from the BGP header.
        :param bgp_message: BGP message containing all updates.
        :return: True if announcements were properly recorded. False otherwise.
        """
        ###
        update = {}
        CIDR = []

        if bgp_message['withdrawn_routes'] != []:
            for item in bgp_message['withdrawn_routes']:
                self.n_withdrawals = 1 + self.n_withdrawals
                update = {
                'timestamp' : timestamp,
                'range' : item,
                'peer_as' : peer_as,
                }
                time = timestamp[0]

                if time not in self.withdrawals:
                    self.withdrawals.update( {time : []})
                    self.withdrawals[time].append(update)
                else:
                    self.withdrawals[time].append(update)


        return True

    def get_next_updates(self):
        """
        You do not need to implement anything in this method.
        This method simply yields the next collection of announcements and
        withdrawals when called. Records yielded are sorted by time.
        :return:
        """
        timestamps = sorted(list(set(self.announcements.keys()).union(set(self.withdrawals.keys()))))
        for timestamp in timestamps:
            update_record = {'announcements': [], 'withdrawals': [], 'timestamp': timestamp}
            if timestamp in self.announcements.keys():
                update_record['announcements'] = self.announcements[timestamp]
            if timestamp in self.withdrawals.keys():
                update_record['withdrawals'] = self.withdrawals[timestamp]
            yield update_record
        yield {'announcements': [], 'withdrawals': [], 'timestamp': None}

    def to_json_helper_function(self, destination_json):
        """
        This is a helper function that converts the MRT file saved in
        `self.filename` to a JSON file and saves it to disk.
        :param destination_json: The location at which to save the converted
        JSON file.
        """
        records = []
        for entry in mrtparse.Reader(self.filename):
            records.append(entry.data)
        with open(destination_json, "w") as fp:
            json.dump(obj=records, fp=fp, indent=2, sort_keys=False)


def main():
    pu = ParseUpdates(filename="./data/updates.20080219.0015.bz2")
    pu.parse_updates()
    pu.to_json_helper_function("./sample-mrt-in-json.json")
    logging.info("Time taken to parse all records: %d second(s)" % pu.time_to_parse)
    logging.info("Routes announced: %d | Routes withdrawn: %d" % (pu.n_announcements, pu.n_withdrawals))
    updates = pu.get_next_updates()
    while True:
        next_updates = updates.__next__()
        if next_updates['timestamp'] is None:
            logging.info("No more updates to process in file: %s" % pu.filename)
            break
        else:
            logging.info("At timestamp: %d | %d announcements | %d withdrawals" % (next_updates['timestamp'],
                                                                                   len(next_updates['announcements']),
                                                                                   len(next_updates['withdrawals'])))


if __name__ == '__main__':
    main()