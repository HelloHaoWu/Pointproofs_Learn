// @title 定义一个类型名为Ciphersuite, 其是u8(即uint8)的包装器;
// @dev 这种写法较直接使用u8的优势是:
//      可以为Ciphersuite添加自己的类型定义方法或特定行为, 但不会影响u8的行为;
// @dev 'pub'是一个关键词, 用于声明公共(public)的项; 具有pub关键词的项可以在模块外访问
pub type Ciphersuite = u8;

// @title bls12_381: Rust实现了BLS12-381椭圆曲线对的库 https://docs.rs/bls12_381/latest/bls12_381/
// @dev 安装方法: cargo add bls12_381 xxx 这里不要使用原生的bls12_381, 这里请使用整合进pairing_plus的bls12_381
// use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};  //xxx 该行调用作废 
use pairing_plus::{bls12_381::*, CurveAffine, CurveProjective};
// use pairing_plus::bls12_381::*;  //xxx 该行调用作废
mod err;
// @dev 导入ff-zeroize, 同时调用ff_zeroize::Field; 非常诡异的是, 导入了这个库之后, 第113行"Fr::one()"不再报错???
//      解释: "use ff::Field"是用于导入ff库中的Field trait的语句. 
//            ff库是一个用于有限域操作的库, 它提供了处理有限域元素的功能. Field这个trait中定义了有限域元素应该具备的行为和操作.
//            通过导入Field trait, 代码可以使用有限域元素的方法和函数, 如加法、乘法、指数运算等. 
//            这样可以方便地在代码中操作和处理有限域中的元素, 例如在密码学、代数运算、密码证明等领域中使用的椭圆曲线密码学算法.
// @dev 导入PrimeField, 使得from_repr方法可以被使用, 因为PrimeField这个trait中定义了from_repr这个fn
use ff_zeroize::{Field, PrimeField};
// @dev 提供Bls12::pairing方法, 应用于pointproofs_pairing函数
use pairing_plus::Engine;
// @dev 该部分在生成alpha时需要, 需要其中的Sha512类型; Digest trait提供了计算哈希值的方法, 即Sha512::new()
use sha2::{Digest, Sha512};
// @dev 该部分在生成alpha时需要, 提供U512类型
use bigint::U512;
// @dev 该部分在生成alpha时需要, 提供U512类型的rem方法
use std::ops::Rem;


#[cfg(not(feature = "group_switched"))]
type PointproofsG1 = G1;
// @notice 默认是不启动group_switched的, 此时通过cfg(not即可决定参数G1与bls12_381中G1的对应关系
#[cfg(not(feature = "group_switched"))]
type PointproofsG2 = G2;
#[cfg(not(feature = "group_switched"))]
type PointproofsG1Affine = G1Affine;
#[cfg(not(feature = "group_switched"))]
type PointproofsG2Affine = G2Affine;

#[cfg(feature = "group_switched")]
type PointproofsG1 = G2Projective;
#[cfg(feature = "group_switched")]
type PointproofsG2 = G1Projective;
#[cfg(feature = "group_switched")]
type PointproofsG1Affine = G2Affine;
#[cfg(feature = "group_switched")]
type PointproofsG2Affine = G1Affine;

// @title 定义椭圆曲线证明者Prover相关的参数
#[derive(Clone, Debug)]  // @dev 结构体用于实现Clone和Debug trait, Clone修饰符允许对结构体克隆, Debug修饰符允许对结构体进行调试
// #[derive()]使得可以自动为结构体实现这些常用trait
pub struct ProverParams {
    pub(crate) ciphersuite: Ciphersuite,  // 指定椭圆曲线对的密码套件
    pub(crate) n: usize,  // 证明者的个数
    // @dev pub(crate)表明pub(公开)关键词指定了范围, 在这里范围是整个crate
    generators: Vec<PointproofsG1Affine>,  // 包含一个由PointproofsG1Affine类型组成的向量, 表示生成元点集合
    pp_len: usize,  // 表示预计算表的长度
    precomp: Vec<PointproofsG1Affine>,  // 包含一个由PointproofsG1Affine类型组成的向量, 表示预计算的结果
}

// @title 定义椭圆曲线验证者Prover相关的参数
#[derive(Clone, Debug)]
pub struct VerifierParams {
    pub(crate) ciphersuite: Ciphersuite,  // 指定椭圆曲线对的密码套件
    pub(crate) n: usize,  // 验证者个数
    generators: Vec<PointproofsG2Affine>,  // 包含一个由PointproofsG2Affine类型组成的向量, 表示生成元点集合
    pp_len: usize,  // 表示预计算表的长度
    precomp: Vec<PointproofsG2Affine>,  // 包含一个由PointproofsG2Affine类型组成的向量, 表示预计算
    // @dev 通过使用预计算值, 可以在验证过程中直接使用已经计算好的结果, 而不必重新计算. 这样可以节省计算时间, 提高验证的效率.
    gt_elt: Fq12,  // 表示BLS12-381椭圆曲线对中的一个元素, 通常用于验证最终结果
}


// @title 定义一个函数, 当且仅当ciphersuite为0时返回true;
// @dev Ciphersuite 密码套件
const VALID_CIPHERSUITE: [u8; 1] = [0u8]; // @dev 定义一个长度为1的u8数组"[u8; 1]", 其唯一元素为0u8"[0u8]"
pub fn check_ciphersuite(csid: Ciphersuite) -> bool {
    VALID_CIPHERSUITE.contains(&csid) // @dev 这里就是判断输入的u8变量是否为0u8
}

/// A wrapper of `hash_to_field` that outputs `Fr`s instead of `FrRepr`s.
/// hash_to_field_pointproofs use SHA 512 to hash a blob into a non-zero field element
pub(crate) fn hash_to_field_pointproofs<Blob: AsRef<[u8]>>(input: Blob) -> Fr {
    // the hash_to_field_repr_pointproofs should already produce a valid Fr element
    // so it is safe to unwrap here
    Fr::from_repr(hash_to_field_repr_pointproofs(input.as_ref())).unwrap()
}

/// Hashes a blob into a non-zero field element.
/// hash_to_field_pointproofs use SHA 512 to hash a blob into a non-zero field element.
pub(crate) fn hash_to_field_repr_pointproofs<Blob: AsRef<[u8]>>(input: Blob) -> FrRepr {
    let mut hasher = Sha512::new();
    hasher.input(input);
    let hash_output = hasher.result();
    let mut t = os2ip_mod_p(&hash_output);

    // if we get 0, return 1
    // this should not happen in practise
    if t == FrRepr([0, 0, 0, 0]) {
        t = FrRepr([1, 0, 0, 0]);
    }
    t
}

/// this is Pointproofs's Octect String to Integer Primitive (os2ip) function
/// https://tools.ietf.org/html/rfc8017#section-4
/// the input is a 64 bytes array, and the output is between 0 and p-1
/// i.e., it performs mod operation by default.
pub(crate) fn os2ip_mod_p(oct_str: &[u8]) -> FrRepr {
    // "For the purposes of this document, and consistent with ASN.1 syntax,
    // an octet string is an ordered sequence of octets (eight-bit bytes).
    // The sequence is indexed from first (conventionally, leftmost) to last
    // (rightmost).  For purposes of conversion to and from integers, the
    // first octet is considered the most significant in the following
    // conversion primitives.
    //
    // OS2IP converts an octet string to a nonnegative integer.
    // OS2IP (X)
    // Input:  X octet string to be converted
    // Output:  x corresponding nonnegative integer
    // Steps:
    // 1.  Let X_1 X_2 ... X_xLen be the octets of X from first to last,
    //  and let x_(xLen-i) be the integer value of the octet X_i for 1
    //  <= i <= xLen.
    // 2.  Let x = x_(xLen-1) 256^(xLen-1) + x_(xLen-2) 256^(xLen-2) +
    //  ...  + x_1 256 + x_0.
    // 3.  Output x. "

    let r_sec = U512::from(oct_str);

    // hard coded modulus p
    let p = U512::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0x73, 0xED, 0xA7, 0x53, 0x29, 0x9D, 0x7D, 0x48, 0x33, 0x39, 0xD8, 0x08, 0x09, 0xA1,
        0xD8, 0x05, 0x53, 0xBD, 0xA4, 0x02, 0xFF, 0xFE, 0x5B, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
        0x00, 0x00, 0x01,
    ]);
    // t = r % p
    let t_sec = r_sec.rem(p);

    // convert t from a U512 into a primefield object s
    let mut tslide: [u8; 64] = [0; 64];
    let bytes: &mut [u8] = tslide.as_mut();
    t_sec.to_big_endian(bytes);

    FrRepr([
        u64::from_be_bytes([
            bytes[56], bytes[57], bytes[58], bytes[59], bytes[60], bytes[61], bytes[62], bytes[63],
        ]),
        u64::from_be_bytes([
            bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53], bytes[54], bytes[55],
        ]),
        u64::from_be_bytes([
            bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46], bytes[47],
        ]),
        u64::from_be_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]),
    ])
}


// @title 定义一个公共函数, 用于通过种子, 密码套件, 长度n来生成证明者和验证者的参数
// @dev 当seed不够长|密码套件不具有有效性|n等于0的时候, 返回各种不同的报错信息
// @dev 仅被用于测试目的
// @notice 在实际部署中，您应该使用"pointproofs-param"crate来确保公共参数的安全性。
pub fn paramgen_from_seed<Blob: AsRef<[u8]>>(
    // @dev 这里由上面的"<Blob: AsRef<[u8]>>"(对函数的trait约束)可知, 其约定Blob是"AsRef<[u8]>"类型而非其他基础类型
    seed: Blob, // @dev AsRef<[u8]>本质上还是u8类型, 但是添加一个方法as_ref(), 该方法能将变量由u8转化为&u8的类型
    ciphersuite: Ciphersuite,
    n: usize,
) -> Result<(ProverParams, VerifierParams), String> {
    // @dev 检查种子是否够长, 此处取将Blob类型转化为&u8类型, 再取其长度
    if seed.as_ref().len() < 32 {
        return Err(err::ERR_SEED_TOO_SHORT.to_owned());
    }

    // @dev 检查是否ciphersuite是否有效
    if !check_ciphersuite(ciphersuite) {
        return Err(err::ERR_CIPHERSUITE.to_owned());
    }
    if n > 65536 {
        return Err(err::ERR_MAX_N.to_owned());
    }

    // @dev 包含后面函数执行的正确信息, 目的是检测函数运行是否出现错误
    Ok(paramgen_from_alpha(
        &hash_to_field_pointproofs(&seed),
        ciphersuite,
        n,
    ))
}

/// BLS::pairing_product的包装器(wrapper)
#[cfg(not(feature = "group_switched"))]
pub(crate) fn pointproofs_pairing(p1: PointproofsG1Affine, q1: PointproofsG2Affine) -> Fq12 {
    Bls12::pairing(p1, q1)  // @dev 这里pairing函数的返回值Fqk在前面有定义, type Fqk = Fq12, 即Fqk就是Fq12
    // @dev pairing中, miller_loop的作用就是生成一些(G1, G2)对 
}

/// @title 参数生成的内部逻辑函数
/// @dev 这部分将永远会运行成功
/// @dev 将不会被在module外调用, 所以没有'pub'
fn paramgen_from_alpha(
    alpha: &Fr, // @dev 'alpha'是一个指向Fr类型的引用, 由"paramgen_from_seed"函数中的seed生成
    ciphersuite: Ciphersuite,
    n: usize,
) -> (ProverParams, VerifierParams) {
    #[cfg(not(debug_assertions))] // @dev 指定了接下来的代码块只在非调试模式下运行
    println!(
        "\n\n\nWarning!!! \nWarning!!! \nWarning!!! \nWarning!!! \n\
        This function (paramgen_from_alpha) shall only be used for developing purpose.\n\
        In deployment you should use `pointproofs-paramgen` crate to ensure \
        the security of the public parameters.\n\
        End of warning.\n\n"
    );
    let mut g1_vec = Vec::with_capacity(2 * n);  // @dev 创建一个容量为2n的空向量 
    // @dev 证明者向量的第i-1处(即论文中向量的第i个位置的数)包含"g1^{alpha^i}", 其中i的范围为"for i ranging from 1 to 2n"
    //      但不包含i本身, 即取从1到2n的所有可能指数值但不取i
    //      (为了保持索引，我们将使用G1::one作为占位符)
    // @dev 'let'后面的'mut'关键词决定了该变量是可变的
    // @dev G1Affine就是该代码中自定义的PointproofsG1Affine
    let mut g2_vec = Vec::with_capacity(n);
    // @dev 验证者向量的第i-1处包含从1到n的所有可能指数值的"g2^{alpha^i}"
    let mut alpha_power = Fr::one();  // @dev one()方法用于返回该字段类型的单位元素, 也称为乘法单位元. 它表示字段中的乘法操作的恒等元素.
    // @notice 某个域中, 加法单位元就是这个数加别的数等于它本身, 乘法单位元就是这个数乘别的数等于它本身
    for _ in 0..n {
        alpha_power.mul_assign(&alpha); // @dev 计算 alpha^i, 将两个Fr类型元素(第一个是alpha_power, 另一个是输入的alpha)相乘
        // @dev 讲解这里为什么能计算alpha^i: 
        //      alpha_power.mul_assign()是将alpha_power这个Fr类型值与alpha相乘, 后赋给它本身;
        //      所以在每次迭代中, alpha_power都会变为alpha_power*alpha, 进而实现计算alpha^i;
        //      这也是为什么要在循环前将alpha_power初始化为Fr::one()的原因, 这样下面的从n到2n-1的循环中也可以继续使用alpha_power
        g1_vec.push(PointproofsG1Affine::one().mul(alpha_power).into_affine()); // @dev 将g1^{alpha^i}添加到g1_vec中; 但它这里好像是基于加法元实现的, 就是{alpha^i}*G1, 不太懂, 还得再看看
        g2_vec.push(PointproofsG2Affine::one().mul(alpha_power).into_affine()); // @dev 将g2^{alpha^i}添加到g2_vec中
    }

    // @dev 跳过g1^{alpha^{n+1}}, 不去计算它
    alpha_power.mul_assign(&alpha);
    g1_vec.push(PointproofsG1::zero().into_affine()); // this 0 is important -- without it, prove will not work correctly

    // @dev 计算剩下的公共参数, 即g1^{alpha^{n+2}}到g1^{alpha^{2n}}
    for _ in n..2 * n - 1 {
        alpha_power.mul_assign(&alpha); // 继续计算 alpha^i
        g1_vec.push(PointproofsG1Affine::one().mul(alpha_power).into_affine()); 
        // @notice PointproofsG1Affine就是G1Affine, 该代码部分用宏替代了
    }

    // @dev 计算验证者(verifier)最后验证需要的验证所需元素gt^{alpha^{n+1}}
    let gt = pointproofs_pairing(g1_vec[0], g2_vec[n - 1]);  // @这部分解释了gt的生成过程

    (
        ProverParams {
            ciphersuite,
            n,
            generators: g1_vec,
            pp_len: 0,
            precomp: Vec::with_capacity(0),
        },
        VerifierParams {
            ciphersuite,
            n,
            generators: g2_vec,
            pp_len: 0,
            precomp: Vec::with_capacity(0),
            gt_elt: gt,
        },
    )
}

// @notice 必须通过cargo run来运行, 否则无法编译通过
fn main() {
    // @title 该部分用来测试check_ciphersuite函数
    // let ciphersuite: Ciphersuite = 0;
    // let is_supported = check_ciphersuite(ciphersuite);
    // println!("Is ciphersuite supported? {}", is_supported);
    let n = 16usize;
    let update_index = n / 2;

    // generate the parameters, and performs pre_computation
    let (mut prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very long Seed", 0, n).unwrap();
    println!("prover_params: {:?}", prover_params);
}
