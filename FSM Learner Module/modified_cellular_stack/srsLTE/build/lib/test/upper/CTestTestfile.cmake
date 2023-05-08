# CMake generated Testfile for 
# Source directory: /home/cyber2slab/LTEUE-State-Fuzzing/FSM_Learner_Module/modified_cellular_stack/srsLTE/lib/test/upper
# Build directory: /home/cyber2slab/LTEUE-State-Fuzzing/FSM_Learner_Module/modified_cellular_stack/srsLTE/build/lib/test/upper
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(rlc_am_data_test "rlc_am_data_test")
add_test(rlc_am_control_test "rlc_am_control_test")
add_test(rlc_am_test "rlc_am_test")
add_test(rlc_am_stress_test "rlc_stress_test" "--mode=AM" "--loglevel" "1" "--sdu_gen_delay" "250")
set_tests_properties(rlc_am_stress_test PROPERTIES  TIMEOUT "3000")
add_test(rlc_um_stress_test "rlc_stress_test" "--mode=UM" "--loglevel" "1")
set_tests_properties(rlc_um_stress_test PROPERTIES  TIMEOUT "3000")
add_test(rlc_tm_stress_test "rlc_stress_test" "--mode=TM" "--loglevel" "1" "--random_opp=false")
set_tests_properties(rlc_tm_stress_test PROPERTIES  TIMEOUT "3000")
add_test(rlc_um_data_test "rlc_um_data_test")
add_test(rlc_um_test "rlc_um_test")
add_test(rlc_common_test "rlc_common_test")
