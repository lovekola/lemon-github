# Inten-driven network telemetry system based on P4 programmable switch.

## 1. Edit your network measurement task using lemon.

There are some examples under `tasks` directory.

## 2. Compile lemon code to P4 code

`python lemon-p4c.py -u demo_name`

P4 code and configuration for system will be generated under `build` directory.

## 3. Compile & Launch P4 switch(Tofino)

Suppose you have installed P4-Studio(bf-sde-9.x) in P4 switch(Tofino)，under $SDE，compile the P4 code:

`./my_p4_16_switch.sh -b --lemon demo_name`

Compile process last about 1 minute and then launch switch:

`./my_p4_16_switch.sh -p demo_name`

Tofino related scripts are under `script-tofino` directory.

## 4. Monitor data plane state using runtime

#### without web

`python lemon-runtime.py --p4_name demo_name` 

system runtime will print measurement results according to configuration files.

#### with web

`python lemon-server.py` 



## 5. Replay traffic and record result.

Use `tcpreplay` replay MAWI traffic in server connected to Tofino with full speed and measurement  results will be generated under `plot` directory.



