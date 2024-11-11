+++
title = 'Ebpf Maps and Concurrency'
date = '2023-12-25'
draft = true
tags = ['ebpf']
+++

Ebpf program obtains a pointer to a map element via `bpf_map_lookup_elem()` helper. However, the element could get removed concurrently. Why don't ebpf programs ever crash by following a dangling element pointer? Further, the application logic could get badly confused by concurrent element modifications. Is there a way to make map updates atomic?

<!--more-->