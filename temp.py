"""import datetime

today = datetime.datetime.now()
date_time = today.strftime("%m/%d/%Y, %H:%M:%S")
print("date and time:",date_time)

from datetime import timezone

timestamp = datetime.replace(tzinfo=timezone.utc).timestamp()
print(timestamp)"""

l = "Accept: txt/html"
print(l[l.index(':') + 2:len(l)])
