# CMake generated Testfile for 
# Source directory: /home/cyber2slab/LTEUE-State-Fuzzing/FSM_Learner_Module/modified_cellular_stack/srsLTE/lib/src/phy/channel/test
# Build directory: /home/cyber2slab/LTEUE-State-Fuzzing/FSM_Learner_Module/modified_cellular_stack/srsLTE/build/lib/src/phy/channel/test
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(fading_channel_test_epa5 "fading_channel_test" "-m" "epa5" "-s" "26.04e6" "-t" "100")
add_test(fading_channel_test_eva70 "fading_channel_test" "-m" "eva70" "-s" "23.04e6" "-t" "100")
add_test(fading_channel_test_etu300 "fading_channel_test" "-m" "etu70" "-s" "23.04e6" "-t" "100")
add_test(delay_channel_test "delay_channel_test" "-m" "10" "-M" "100" "-t" "1000" "-T" "1" "-s" "1.92e6")
