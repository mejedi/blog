+++
title = 'Ebpf Maps and Concurrency'
draft = true
tags = ['ebpf']
+++

Via `bpf_map_lookup_elem()`, ebpf program obtains a pointer to an element stored in a map. But the element could be removed concurrently. Why don't ebpf programs ever crash by following a dangling element pointer? Further, the application logic could get badly confused by concurrent element modifications. Is there a way to make map updates atomic?