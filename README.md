# TCP Load Balancer

A prototype of a load balancer for splitting single TCP streams into multiple outputs. Designed for Cribl Stream.

## Config Options

| Argument            | Environment Variable              | Description                                                                 | Default   |
|---------------------|-----------------------------------|-----------------------------------------------------------------------------|-----------|
| -h &#124; --host    | LB_RECEIVER_HOST                  | Receiver host IP address                                                    | `0.0.0.0` |
| -p &#124; --port    | LB_RECEIVER_PORT                  | Receiver port                                                               | `1514`    |
| -t &#124; --threads | LB_WORKER_THREADS_PER_SENDER_HOST | The number of threads per sending host                                      | `10`      |
| -s &#124; --senders | LB_SENDER_HOSTS                   | Comma separated list of sending hosts. Hosts should be in host:port format. | `None`    |
| -k &#124; --key     | LB_RECEIVER_TLS_KEY_FILE          | TLS private key file location                                               | `None`    |
| -c &#124; --cert    | LB_RECEIVER_TLS_CERT_FILE         | TLS certificate file location                                               | `None`    |
| --usetls            | LB_SENDER_TLS                     | Enable TLS connections for senders.                                         | `False`   |
| --tlsverify         | LB_SENDER_TLS_VERIFY              | Verify TLS certificate information for senders.                             | `False`   |
| --cacert            | LB_SENDER_TLS_CACERT              | Sender TLS CA Certificate file or directory.                                | `None`    |
