+++
title = 'Counting Items in Ebpf Map'
draft = true
tags = ['ebpf']
+++

Ebpf maps have fixed capacity. Once it fills up, all attempts to insert more entries will fail. Monitoring map utilization continuously could be a good idea. But counting items in a ebpf map is surprisingly non-trivial.

<!--more-->

As of kernel 6.5, there is no API yet to query the number of items in a ebpf map. We could extract items from a map and literally count them. To get some idea on how (in)efficient it is, I did a simple benchmark varying the number of items in a hash map.

TODO plot

As expected, the time it takes depends on the number of items in a map.

Maps reaching 100 million entries are not unheard of.