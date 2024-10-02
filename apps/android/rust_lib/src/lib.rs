mod nizk;

// Import JNI types
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_com_example_rustbenchmarkapp_MainActivity_runBenchmark(
    mut env: JNIEnv,
    _class: JClass,
    j_r1cs_path: JString,
    j_witness_path: JString,
) -> jstring {
    let r1cs_path: String = env.get_string(&j_r1cs_path).expect("Invalid r1cs_path").into();
    let witness_path: String = env.get_string(&j_witness_path).expect("Invalid witness_path").into();

    let result = nizk::run_benchmark(r1cs_path, witness_path);

    let output = env.new_string(result).expect("Couldn't create Java string!");
    output.into_raw()
}
