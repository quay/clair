Display a live stream of one or more containers' resource usage statistics

# Format

   Pretty-print containers statistics using a Go template.
   Valid placeholders:
      .Container - Container name or ID.
      .Name - Container name.
      .ID - Container ID.
      .CPUPerc - CPU percentage.
      .MemUsage - Memory usage.
      .NetIO - Network IO.
      .BlockIO - Block IO.
      .MemPerc - Memory percentage (Not available on Windows).
      .PIDs - Number of PIDs (Not available on Windows).

# EXAMPLES

Running `docker container stats` on all running containers

    $ docker container stats
    CONTAINER           CPU %               MEM USAGE / LIMIT     MEM %               NET I/O             BLOCK I/O
    1285939c1fd3        0.07%               796 KiB / 64 MiB        1.21%               788 B / 648 B       3.568 MB / 512 KB
    9c76f7834ae2        0.07%               2.746 MiB / 64 MiB      4.29%               1.266 KB / 648 B    12.4 MB / 0 B
    d1ea048f04e4        0.03%               4.583 MiB / 64 MiB      6.30%               2.854 KB / 648 B    27.7 MB / 0 B

Running `docker container stats` on multiple containers by name and id.

    $ docker container stats fervent_panini 5acfcb1b4fd1
    CONTAINER           CPU %               MEM USAGE/LIMIT     MEM %               NET I/O
    5acfcb1b4fd1        0.00%               115.2 MiB/1.045 GiB   11.03%              1.422 kB/648 B
    fervent_panini      0.02%               11.08 MiB/1.045 GiB   1.06%               648 B/648 B
