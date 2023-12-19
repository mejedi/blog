+++
title = 'Counting Items in Ebpf Map'
draft = true
tags = ['ebpf']
+++

Ebpf maps have fixed capacity. Once it fills up, further attempts to insert more entries will fail. Monitoring map utilization continuously could be a good idea. But counting items in ebpf map is surprisingly non-trivial.