# logging_project
EFK stack

This project was created to gain some experience with EFK stack: Elasticsearch, Fluentd and Kibana.
All historical data is not real and created only for this project.
Full project was automated with Ansible except graphs in Kibana.


### Initial state

* Three application servers 

* Ubuntu 18.04

* Nginx Web servers on them which proxy to Docker containers

### Targets

* Reading of all current and historical system logs.

* Reading of all current and historical Docker Containers logs and Nginx logs.

* Create Gaphs in Kibana and find:

    * TOP-7 IP clients accessing web servers.

    * Are all user sessions when accessing web resources safe?

    * Determine the average number of active containers per month

    * Determine the average lifetime of a single container.

    * identify anomalies, if any exist.

 
### Log flow diagram

![Elastic_scheme](https://github.com/DevEnv-94/logging_project/blob/master/images/scheme.png)

### Fluentd config file on app servers

```bash

<source>
  @type tail
  read_from_head true
  path /var/lib/docker/containers/*/*.log
  pos_file /var/log/td-agent/docker.log.pos
  tag docker.{{ ansible_hostname }}.*
  <parse>
    @type json
    time_type string
    keep_time_key true  
    time_format "%Y-%m-%dT%H:%M:%S.%L%Z"
  </parse>
</source>

<source>
  @type tail
  read_from_head true
  path /var/log/syslog
  pos_file /var/log/td-agent/syslog.log.pos
  tag syslogs.{{ ansible_hostname }}.*
  <parse>
    @type syslog
    keep_time_key true
  </parse>
</source>

<source>
  @type tail
  read_from_head true
  path /var/log/nginx/access.log
  pos_file /var/log/td-agent/nginx.log.pos
  tag nginx.{{ ansible_hostname }}.*
  <parse>
    @type nginx
    keep_time_key true
  </parse>
</source>

<filter syslogs.**>
  @type record_transformer
  enable_ruby true

  <record>
    tag "${tag_parts[0]}"
    host "${tag_parts[1]}"
    file "${tag_parts[4]}"
    @timestamp ${time.strftime('%Y-%m-%dT%H:%M:%S')}
  </record>
</filter>

<filter nginx.**>
  @type record_transformer
  enable_ruby true

  <record>
    tag "${tag_parts[0]}"
    host "${tag_parts[1]}"
    file "${tag_parts[5]}"
    @timestamp ${time.strftime('%Y-%m-%dT%H:%M:%S')} 
  </record>
</filter>

<filter docker.**>
  @type record_transformer
  enable_ruby true

  <record>
    tag "${tag_parts[0]}"
    host "${tag_parts[1]}"
    container "${tag_parts[6]}"
    @timestamp ${time.strftime('%Y-%m-%dT%H:%M:%S')}
  </record>
</filter>

<match {docker.**,syslogs.**,nginx.**}>
  @type kafka2
  brokers {{ hostvars[groups['fluent_aggregator'][0]]['ansible_eth1']['ipv4']['address'] }}:9092
  default_topic logs.apps
  max_send_limit_bytes 15000000
  <format>
    @type json
  </format>
  <buffer>
    @type file
    path /var/log/td-agent/logs_buf/
    chunk_limit_size 4MB
    flush_mode interval
    flush_interval 2s
    flush_at_shutdown true  
  </buffer>
</match>

```

### Server.properties kafka file (only what was changed, all others parametres default)

```bash

listeners=PLAINTEXT://{{ ansible_eth1.ipv4.address }}:9092
delete.topic.enable = true
message.max.bytes=21000000

```

### Fluentd config file on Fluentd_aggregator server

```bash

<source>
  @type kafka

  brokers {{ ansible_eth1.ipv4.address }}:9092
  topics logs.apps
  format json
  add_prefix kafka

</source>

<match kafka.**>
  @type rewrite_tag_filter

  <rule>
    key tag
    pattern /(^.+)/
    tag $1
  </rule>
  
</match>

<match {docker,syslogs,nginx}>
  @type elasticsearch
  hosts {{ hostvars[groups['elasticsearch'][0]]['ansible_eth1']['ipv4']['address'] }}:9200,{{ hostvars[groups['elasticsearch'][1]]['ansible_eth1']['ipv4']['address'] }}:9200,{{ hostvars[groups['elasticsearch'][2]]['ansible_eth1']['ipv4']['address'] }}:9200
  index_name ${tag}
  request_timeout 20s

    <buffer>
      @type file
      path /var/log/td-agent/log_buf/
      chunk_limit_size 6MB
      flush_mode interval
      flush_interval 2s
      flush_at_shutdown true
    </buffer>
</match>

```

### Kibana config file

```bash

server.port: 5601
server.host: "{{ ansible_eth1.ipv4.address }}"
server.name: "Kibana"
elasticsearch.hosts: 
  - http://{{ hostvars[groups['elasticsearch'][0]]['ansible_eth1']['ipv4']['address'] }}:9200
  - http://{{ hostvars[groups['elasticsearch'][1]]['ansible_eth1']['ipv4']['address'] }}:9200
  - http://{{ hostvars[groups['elasticsearch'][2]]['ansible_eth1']['ipv4']['address'] }}:9200
# Enables you to specify a file where Kibana stores log output.
logging:
  appenders:
    file:
      type: file
      fileName: /var/log/kibana/kibana.log
      layout:
        type: json
  root:
    appenders:
      - default
      - file

pid.file: /run/kibana/kibana.pid

```

### Elasticsearch cluster's elasticsearvh.yml config file

```bash

cluster.name: es_cluster

node.name: es-node-{{node_number}}

{% if node_number == 2 -%}
node.roles: [ data, master, voting_only ]
{% else -%}
node.roles: [ data, master ]
{% endif %}

network.host: {{ ansible_eth1.ipv4.address }}

http.port: 9200

discovery.seed_hosts: ["{{ hostvars[groups['elasticsearch'][0]]['ansible_eth1']['ipv4']['address'] }}", "{{ hostvars[groups['elasticsearch'][1]]['ansible_eth1']['ipv4']['address'] }}","{{ hostvars[groups['elasticsearch'][2]]['ansible_eth1']['ipv4']['address'] }}"]

{% if node_number == 1 -%}
discovery.type: multi-node
cluster.initial_master_nodes: ["es-node-1"]
{% else -%}
 
{% endif %}

path.data: /var/lib/elasticsearch

path.logs: /var/log/elasticsearch

xpack.security.enabled: false

xpack.security.enrollment.enabled: false

xpack.security.http.ssl:
  enabled: true
  keystore.path: certs/http.p12


xpack.security.transport.ssl:
  enabled: true
  verification_mode: certificate
  keystore.path: certs/transport.p12
  truststore.path: certs/transport.p12

  ```

#### Heap_size.j2 file 

```bash

-Xms{{Xms_heap_size}}
-Xmx{{Xmx_heap_size}}

```

### Nginx config file on flunetd_aggregator server for HTTPS and proxy to Kibana

```bash

log_format nginx '$remote_addr - $remote_user [$time_local] "$request" '
                         '$status $body_bytes_sent "$http_referer" '
                         '"$http_user_agent" "$http_x_forwarded_for" '
                        '$upstream_response_time $request_time';


map $http_upgrade $connection_upgrade {
   default upgrade;
   '' close;
  }

server {
	listen 80 ;

	root /var/www/html;

	index index.html index.htm index.nginx-debian.html;

	server_name {{domain}} www.{{domain}};

  access_log /var/log/nginx/nginx.access.log nginx;

	location / {
	  return 301 https://$host$request_uri;
	}

}

upstream kibana {
  server {{ansible_eth1.ipv4.address}}:5601;
}

server {
    listen 443 ssl http2 default_server;

    auth_basic_user_file /etc/nginx/htpasswd;
    auth_basic "Restricted";

    access_log /var/log/nginx/nginx.access.log nginx;

    index index.html index.php index.htm index.nginx-debian.html;

    ssl_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{domain}}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;  # about 40000 sessions
    ssl_session_tickets off;

    # curl https://ssl-config.mozilla.org/ffdhe2048.txt > /path/to/dhparam
    ssl_dhparam /etc/nginx/dhparam;


    # intermediate configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS (ngx_http_headers_module is required) (63072000 seconds)
    add_header Strict-Transport-Security "max-age=63072000" always;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # verify chain of trust of OCSP response using Root CA and Intermediate certs
    ssl_trusted_certificate /etc/letsencrypt/live/{{domain}}/fullchain.pem;

    # replace with the IP address of your resolver
    resolver 8.8.8.8;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
      proxy_pass http://kibana;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection 'upgrade';
      proxy_set_header Host $host;
      proxy_cache_bypass $http_upgrade;
    }
    

}

```

### Graphs on kibana and Answers to the questions which is above.

##### TOP-7 IP clients accessing web servers.

![TOP7](https://github.com/DevEnv-94/logging_project/blob/master/images/Screenshot%202022-06-15%20at%2023.56.40.png) 

* TOP-7 IPs:
    * 242.235.17.94
    * 145.25.203.51
    * 190.166.213.61
    * 186.123.134.217
    * 146.252.231.166
    * 167.8.71.90
    * 229.77.64.223

* This represents 11.5% of the total requests

##### Are all user sessions when accessing web resources safe?

![user_session](https://github.com/DevEnv-94/logging_project/blob/master/images/Screenshot%202022-06-15%20at%2023.54.51.png)

* 12,5% of user session was unsafe
* Unsafe user session was only on http://pay.shop.com


##### Determine the average number of active containers per month

![containers_per_month](https://github.com/DevEnv-94/logging_project/blob/master/images/Screenshot%202022-06-15%20at%2023.53.36.png)

* Unic count of containers divided to 12 = 294

* if to be completely accurate it would be Unic count of containers divided to 357days(date range of historical data) multiply 366(days in 2020) and then divide to 12. ~~ 301,4

##### Determine the average lifetime of a single container.

![GET_request](https://github.com/DevEnv-94/logging_project/blob/master/images/Screenshot%202022-06-15%20at%2023.58.40.png)
![Answer](https://github.com/DevEnv-94/logging_project/blob/master/images/Screenshot%202022-06-15%20at%2023.58.57.png)

* Avarage lifetime of a single container is ~ 185.12 days


##### Anomalies if exist

![anomalies](https://github.com/DevEnv-94/logging_project/blob/master/images/Screenshot%202022-06-15%20at%2023.31.59.png)
![anomalies](https://github.com/DevEnv-94/logging_project/blob/master/images/Screenshot%202022-06-15%20at%2023.40.17.png)
![anomalies](https://github.com/DevEnv-94/logging_project/blob/master/images/Screenshot%202022-06-15%20at%2023.48.25.png)
![anomalies](https://github.com/DevEnv-94/logging_project/blob/master/images/Screenshot%202022-06-15%20at%2023.51.55.png)


Anomalies

* Count request to sites was stably ~160-170 records per day in January, then in February grew up to ~ 500 request per day, dropped sharply around mid-March to ~330 request per day and again in April grew up to ~500 request per day and was satbly all to the last day of historical data. But Count of working containers and containers logs grew steadily all the time.

* Working containers per day and containers logs increased only in the first half of the month.

* The last day of historical data count of containers logs was dropped sharply 4 times, but working containers and request to sites this day was stable.

