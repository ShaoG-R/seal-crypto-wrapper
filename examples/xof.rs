use seal_crypto_wrapper::error::Result;
use seal_crypto_wrapper::prelude::*;
use seal_crypto_wrapper::traits::XofAlgorithmTrait;

fn main() -> Result<()> {
    // 1. Select a XOF algorithm.
    // 1. 选择一个 XOF 算法。
    let algorithm = XofAlgorithm::build().shake128();
    println!("Selected XOF algorithm: {:?}", algorithm);

    // 2. Get the algorithm wrapper.
    // 2. 获取算法包装器。
    let xof = algorithm.into_xof_wrapper();
    println!("Got XOF wrapper.");

    // 3. Define the input keying material, salt, and info.
    // 3. 定义输入密钥材料、盐和信息。
    let ikm = b"input keying material";
    let salt = b"some salt";
    let info = b"some info";
    println!("IKM: {:?}", String::from_utf8_lossy(ikm));
    println!("Salt: {:?}", String::from_utf8_lossy(salt));
    println!("Info: {:?}", String::from_utf8_lossy(info));

    // 4. Create a XOF reader.
    // 4. 创建一个 XOF 读取器。
    let mut reader = xof.reader(ikm, Some(salt), Some(info))?;
    println!("Created XOF reader.");

    // 5. Read 32 bytes from the reader.
    // 5. 从读取器中读取 32 字节。
    let mut output1 = [0u8; 32];
    reader.read(&mut output1);
    println!("Read 32 bytes from reader.");

    // 6. Read another 64 bytes from the reader.
    // 6. 从读取器中再读取 64 字节。
    let mut output2 = [0u8; 64];
    reader.read(&mut output2);
    println!("Read 64 bytes from reader.");

    // 7. Verify that the outputs are different.
    // 7. 验证输出是不同的。
    assert_ne!(&output1[..], &output2[..32]);
    println!("Successfully verified that the outputs are different!");

    println!("Output 1 (32 bytes): {:?}", &output1);
    println!("Output 2 (64 bytes): {:?}", &output2);

    Ok(())
}
