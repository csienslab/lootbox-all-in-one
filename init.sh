. /venv/bin/activate
# start headstart server
(
    cd headstart_py && \
    python -m headstart.public_key priv.key pub.key && \
    chmod +x ./run_server.sh && \
    ./run_server.sh > logs.txt 2>&1
) &
# enter loot-box-protocol
cd loot-box-protocol
printf "\e[1;32m[Loot Box Protocol] Shell\e[0m\n"
echo "Try 'python interactive_server.py' for our interactive server for probability verification protocol"
echo "And 'python ProbabilityVerification.py' can be used to generate our experimental results"
