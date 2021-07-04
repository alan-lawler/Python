import time
import os
import re
import datetime
import lookup

# regular expression to extract internal to external traffic from Sophos XG Firewall logs
reg = r"^.+date=(?P<date>\d{4}-\d{2}-\d{2})\stime=(?P<time>\d{2}:\d{2}:\d{2}).+log_subtype=\"(?P<action>\w+)\"\s" \
      r".+application=\"(?P<application>.+|)\"\sapplication_risk=.+src_ip=(?P<src>10.10.\d{2}\.\d{1,3})." \
      r"src_country_code=R1\sdst_ip=(?P<dest>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\sdst_country_code=(?P<country>\w+)" \
      r"\sprotocol=\"(?P<protocol>\w+)\"\ssrc_port=(?P<src_port>\d+)\sdst_port=(?P<dst_port>\d+).+"

path = '/home/ubuntu/syslog/'


# tail() function accepts a file as a paramater and then monitors the file for new log events.
# Each log event is returned to the caller
def tail(file):
    today = datetime.date.today()
    file.seek(0, os.SEEK_END)

    # Breaks the while loop when the date changes. The read() function will pickup new file with today's date and
    # send it to tail().
    while datetime.date.today() == today:
        line = file.readline()
        if not line:
            # time.sleep(0.1)
            continue
        yield line


# The read() function looks for a log file with with today's date in 'YYYY-MM-DD.log' format. It sends the log file to
# tail(), which returns new log events as the log file is updated by syslog-ng.
def read():
    # Try statement is required because when the date changes, there will be a few seconds delay before syslog-ng
    # creates the new file.
    try:
        while True:
            filename = path + str(datetime.date.today()) + ".log"  # 'YYYY-MM-DD.log' format
            logfile = open(filename)
            loglines = tail(logfile)  # send file to tail()


            for line in loglines:
                match = re.search(reg, line)  # looks for log events based on regex
                if match:  # extracts data based on capture group
                    d = match.group(1)
                    t = match.group(2)
                    action = match.group(3)
                    # app = match.group(4)
                    src = match.group(5)
                    dest = match.group(6)
                    # country = match.group(7)
                    protocol = match.group(8)
                    # src_port = match.group(9)
                    dest_port = match.group(10)

                    # sends data to lookups function in lookup.py
                    lookup.lookups(d, t, src, dest, dest_port, protocol, action)

                    del match  # erases match variable

    except:
        # read()  # restarts application if log file doesn't exist
        time.sleep(1)
        read()


if __name__ == '__main__':
    read()
