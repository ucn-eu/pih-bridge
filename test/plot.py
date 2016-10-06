import json
import matplotlib.pyplot as plt
import sys

font = {
    'family': 'serif',
    'color': 'darkred',
    'weight': 'normal',
    'size': 16,
}

print("Read from: " + sys.argv[1] + "\nOutput to:" +  sys.argv[2])

input_file = sys.argv[1]
output_file = sys.argv[2]

raw = open(input_file)
json_arr = json.load(raw)

tup_arr = [(obj['cnt'], obj['time']) for obj in json_arr]
tup_arr.sort()
cnt, time = zip(*tup_arr)
time = [ns / 1e6 for ns in time]

plt.plot(cnt, time)
plt.title('PIH-bridge insertion profile')
plt.ylabel('operation latency (ms)')
plt.xlabel('number of rules inserted')

plt.savefig(output_file)
