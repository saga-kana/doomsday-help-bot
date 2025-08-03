#for i in `seq 0 8`; do tmux pipe-pane -t capture1:$i "sh -c 'stdbuf -oL grep -i help > /tmp/capture1_$i.log'"; done
#for i in `seq 0 8`; do tmux pipe-pane -t capture3:$i "sh -c 'stdbuf -oL grep -i help > /tmp/capture3_$i.log'"; done
#for i in `seq 0 9`; do tmux pipe-pane -t capture4:$i "sh -c 'stdbuf -oL grep -i help > /tmp/capture4_$i.log'"; done
for i in `seq 0 8`; do tmux pipe-pane -t capture1:$i "sh -c 'stdbuf -oL tee /tmp/capture1_${i}_all.log | stdbuf -oL grep -i help > /tmp/capture1_$i.log'"; done
for i in `seq 0 8`; do tmux pipe-pane -t capture3:$i "sh -c 'stdbuf -oL tee /tmp/capture3_${i}_all.log | stdbuf -oL grep -i help > /tmp/capture3_$i.log'"; done
for i in `seq 0 9`; do tmux pipe-pane -t capture4:$i "sh -c 'stdbuf -oL tee /tmp/capture4_${i}_all.log | stdbuf -oL grep -i help > /tmp/capture4_$i.log'"; done
