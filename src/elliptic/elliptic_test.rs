use std::str::FromStr;
use crate::elliptic::{CurveP224, EllipticCurve, CurveP256};
use rmath::bigint::{BigInt, Nat};

#[test]
fn elliptic_on_curve() {
    let p224 = CurveP224::new().unwrap();
    
    assert!(p224.is_on_curve(p224.curve_params().base_point().0, p224.curve_params().base_point().1));
}

#[test]
fn elliptic_off_curve() {
    let p224 = CurveP224::new().unwrap();
    let (x, y) = (BigInt::from(1u32), BigInt::from(1u32));
    
    assert!(!p224.is_on_curve(&x, &y));
}

/// (k, x, y)
const P224_BASE_MULT_TESTS: [(&str, &str, &str); 52] = [
    (
        "1",
        "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
        "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
    ),
    (
        "2",
        "0x706a46dc76dcb76798e60e6d89474788d16dc18032d268fd1a704fa6",
        "0x1c2b76a7bc25e7702a704fa986892849fca629487acf3709d2e4e8bb",
    ),
    (
        "3",
        "0xdf1b1d66a551d0d31eff822558b9d2cc75c2180279fe0d08fd896d04",
        "0xa3f7f03cadd0be444c0aa56830130ddf77d317344e1af3591981a925",
    ),
    (
        "4",
        "0xae99feebb5d26945b54892092a8aee02912930fa41cd114e40447301",
        "0x482580a0ec5bc47e88bc8c378632cd196cb3fa058a7114eb03054c9",
    ),
    (
        "5",
        "0x31c49ae75bce7807cdff22055d94ee9021fedbb5ab51c57526f011aa",
        "0x27e8bff1745635ec5ba0c9f1c2ede15414c6507d29ffe37e790a079b",
    ),
    (
        "6",
        "0x1f2483f82572251fca975fea40db821df8ad82a3c002ee6c57112408",
        "0x89faf0ccb750d99b553c574fad7ecfb0438586eb3952af5b4b153c7e",
    ),
    (
        "7",
        "0xdb2f6be630e246a5cf7d99b85194b123d487e2d466b94b24a03c3e28",
        "0xf3a30085497f2f611ee2517b163ef8c53b715d18bb4e4808d02b963",
    ),
    (
        "8",
        "0x858e6f9cc6c12c31f5df124aa77767b05c8bc021bd683d2b55571550",
        "0x46dcd3ea5c43898c5c5fc4fdac7db39c2f02ebee4e3541d1e78047a",
    ),
    (
        "9",
        "0x2fdcccfee720a77ef6cb3bfbb447f9383117e3daa4a07e36ed15f78d",
        "0x371732e4f41bf4f7883035e6a79fcedc0e196eb07b48171697517463",
    ),
    (
        "10",
        "0xaea9e17a306517eb89152aa7096d2c381ec813c51aa880e7bee2c0fd",
        "0x39bb30eab337e0a521b6cba1abe4b2b3a3e524c14a3fe3eb116b655f",
    ),
    (
        "11",
        "0xef53b6294aca431f0f3c22dc82eb9050324f1d88d377e716448e507c",
        "0x20b510004092e96636cfb7e32efded8265c266dfb754fa6d6491a6da",
    ),
    (
        "12",
        "0x6e31ee1dc137f81b056752e4deab1443a481033e9b4c93a3044f4f7a",
        "0x207dddf0385bfdeab6e9acda8da06b3bbef224a93ab1e9e036109d13",
    ),
    (
        "13",
        "0x34e8e17a430e43289793c383fac9774247b40e9ebd3366981fcfaeca",
        "0x252819f71c7fb7fbcb159be337d37d3336d7feb963724fdfb0ecb767",
    ),
    (
        "14",
        "0xa53640c83dc208603ded83e4ecf758f24c357d7cf48088b2ce01e9fa",
        "0xd5814cd724199c4a5b974a43685fbf5b8bac69459c9469bc8f23ccaf",
    ),
    (
        "15",
        "0xbaa4d8635511a7d288aebeedd12ce529ff102c91f97f867e21916bf9",
        "0x979a5f4759f80f4fb4ec2e34f5566d595680a11735e7b61046127989",
    ),
    (
        "16",
        "0xb6ec4fe1777382404ef679997ba8d1cc5cd8e85349259f590c4c66d",
        "0x3399d464345906b11b00e363ef429221f2ec720d2f665d7dead5b482",
    ),
    (
        "17",
        "0xb8357c3a6ceef288310e17b8bfeff9200846ca8c1942497c484403bc",
        "0xff149efa6606a6bd20ef7d1b06bd92f6904639dce5174db6cc554a26",
    ),
    (
        "18",
        "0xc9ff61b040874c0568479216824a15eab1a838a797d189746226e4cc",
        "0xea98d60e5ffc9b8fcf999fab1df7e7ef7084f20ddb61bb045a6ce002",
    ),
    (
        "19",
        "0xa1e81c04f30ce201c7c9ace785ed44cc33b455a022f2acdbc6cae83c",
        "0xdcf1f6c3db09c70acc25391d492fe25b4a180babd6cea356c04719cd",
    ),
    (
        "20",
        "0xfcc7f2b45df1cd5a3c0c0731ca47a8af75cfb0347e8354eefe782455",
        "0xd5d7110274cba7cdee90e1a8b0d394c376a5573db6be0bf2747f530",
    ),
    (
        "112233445566778899",
        "0x61f077c6f62ed802dad7c2f38f5c67f2cc453601e61bd076bb46179e",
        "0x2272f9e9f5933e70388ee652513443b5e289dd135dcc0d0299b225e4",
    ),
    (
        "112233445566778899112233445566778899",
        "0x29895f0af496bfc62b6ef8d8a65c88c613949b03668aab4f0429e35",
        "0x3ea6e53f9a841f2019ec24bde1a75677aa9b5902e61081c01064de93",
    ),
    (
        "6950511619965839450988900688150712778015737983940691968051900319680",
        "0xab689930bcae4a4aa5f5cb085e823e8ae30fd365eb1da4aba9cf0379",
        "0x3345a121bbd233548af0d210654eb40bab788a03666419be6fbd34e7",
    ),
    (
        "13479972933410060327035789020509431695094902435494295338570602119423",
        "0xbdb6a8817c1f89da1c2f3dd8e97feb4494f2ed302a4ce2bc7f5f4025",
        "0x4c7020d57c00411889462d77a5438bb4e97d177700bf7243a07f1680",
    ),
    (
        "13479971751745682581351455311314208093898607229429740618390390702079",
        "0xd58b61aa41c32dd5eba462647dba75c5d67c83606c0af2bd928446a9",
        "0xd24ba6a837be0460dd107ae77725696d211446c5609b4595976b16bd",
    ),
    (
        "13479972931865328106486971546324465392952975980343228160962702868479",
        "0xdc9fa77978a005510980e929a1485f63716df695d7a0c18bb518df03",
        "0xede2b016f2ddffc2a8c015b134928275ce09e5661b7ab14ce0d1d403",
    ),
    (
        "11795773708834916026404142434151065506931607341523388140225443265536",
        "0x499d8b2829cfb879c901f7d85d357045edab55028824d0f05ba279ba",
        "0xbf929537b06e4015919639d94f57838fa33fc3d952598dcdbb44d638",
    ),
    (
        "784254593043826236572847595991346435467177662189391577090",
        "0x8246c999137186632c5f9eddf3b1b0e1764c5e8bd0e0d8a554b9cb77",
        "0xe80ed8660bc1cb17ac7d845be40a7a022d3306f116ae9f81fea65947",
    ),
    (
        "13479767645505654746623887797783387853576174193480695826442858012671",
        "0x6670c20afcceaea672c97f75e2e9dd5c8460e54bb38538ebb4bd30eb",
        "0xf280d8008d07a4caf54271f993527d46ff3ff46fd1190a3f1faa4f74",
    ),
    (
        "205688069665150753842126177372015544874550518966168735589597183",
        "0xeca934247425cfd949b795cb5ce1eff401550386e28d1a4c5a8eb",
        "0xd4c01040dba19628931bc8855370317c722cbd9ca6156985f1c2e9ce",
    ),
    (
        "13479966930919337728895168462090683249159702977113823384618282123295",
        "0xef353bf5c73cd551b96d596fbc9a67f16d61dd9fe56af19de1fba9cd",
        "0x21771b9cdce3e8430c09b3838be70b48c21e15bc09ee1f2d7945b91f",
    ),
    (
        "50210731791415612487756441341851895584393717453129007497216",
        "0x4036052a3091eb481046ad3289c95d3ac905ca0023de2c03ecd451cf",
        "0xd768165a38a2b96f812586a9d59d4136035d9c853a5bf2e1c86a4993",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368041",
        "0xfcc7f2b45df1cd5a3c0c0731ca47a8af75cfb0347e8354eefe782455",
        "0xf2a28eefd8b345832116f1e574f2c6b2c895aa8c24941f40d8b80ad1",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368042",
        "0xa1e81c04f30ce201c7c9ace785ed44cc33b455a022f2acdbc6cae83c",
        "0x230e093c24f638f533dac6e2b6d01da3b5e7f45429315ca93fb8e634",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368043",
        "0xc9ff61b040874c0568479216824a15eab1a838a797d189746226e4cc",
        "0x156729f1a003647030666054e208180f8f7b0df2249e44fba5931fff",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368044",
        "0xb8357c3a6ceef288310e17b8bfeff9200846ca8c1942497c484403bc",
        "0xeb610599f95942df1082e4f9426d086fb9c6231ae8b24933aab5db",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368045",
        "0xb6ec4fe1777382404ef679997ba8d1cc5cd8e85349259f590c4c66d",
        "0xcc662b9bcba6f94ee4ff1c9c10bd6ddd0d138df2d099a282152a4b7f",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368046",
        "0xbaa4d8635511a7d288aebeedd12ce529ff102c91f97f867e21916bf9",
        "0x6865a0b8a607f0b04b13d1cb0aa992a5a97f5ee8ca1849efb9ed8678",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368047",
        "0xa53640c83dc208603ded83e4ecf758f24c357d7cf48088b2ce01e9fa",
        "0x2a7eb328dbe663b5a468b5bc97a040a3745396ba636b964370dc3352",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368048",
        "0x34e8e17a430e43289793c383fac9774247b40e9ebd3366981fcfaeca",
        "0xdad7e608e380480434ea641cc82c82cbc92801469c8db0204f13489a",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368049",
        "0x6e31ee1dc137f81b056752e4deab1443a481033e9b4c93a3044f4f7a",
        "0xdf82220fc7a4021549165325725f94c3410ddb56c54e161fc9ef62ee",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368050",
        "0xef53b6294aca431f0f3c22dc82eb9050324f1d88d377e716448e507c",
        "0xdf4aefffbf6d1699c930481cd102127c9a3d992048ab05929b6e5927",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368051",
        "0xaea9e17a306517eb89152aa7096d2c381ec813c51aa880e7bee2c0fd",
        "0xc644cf154cc81f5ade49345e541b4d4b5c1adb3eb5c01c14ee949aa2",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368052",
        "0x2fdcccfee720a77ef6cb3bfbb447f9383117e3daa4a07e36ed15f78d",
        "0xc8e8cd1b0be40b0877cfca1958603122f1e6914f84b7e8e968ae8b9e",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368053",
        "0x858e6f9cc6c12c31f5df124aa77767b05c8bc021bd683d2b55571550",
        "0xfb9232c15a3bc7673a3a03b0253824c53d0fd1411b1cabe2e187fb87",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368054",
        "0xdb2f6be630e246a5cf7d99b85194b123d487e2d466b94b24a03c3e28",
        "0xf0c5cff7ab680d09ee11dae84e9c1072ac48ea2e744b1b7f72fd469e",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368055",
        "0x1f2483f82572251fca975fea40db821df8ad82a3c002ee6c57112408",
        "0x76050f3348af2664aac3a8b05281304ebc7a7914c6ad50a4b4eac383",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368056",
        "0x31c49ae75bce7807cdff22055d94ee9021fedbb5ab51c57526f011aa",
        "0xd817400e8ba9ca13a45f360e3d121eaaeb39af82d6001c8186f5f866",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368057",
        "0xae99feebb5d26945b54892092a8aee02912930fa41cd114e40447301",
        "0xfb7da7f5f13a43b81774373c879cd32d6934c05fa758eeb14fcfab38",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368058",
        "0xdf1b1d66a551d0d31eff822558b9d2cc75c2180279fe0d08fd896d04",
        "0x5c080fc3522f41bbb3f55a97cfecf21f882ce8cbb1e50ca6e67e56dc",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368059",
        "0x706a46dc76dcb76798e60e6d89474788d16dc18032d268fd1a704fa6",
        "0xe3d4895843da188fd58fb0567976d7b50359d6b78530c8f62d1b1746",
    ),
    (
        "26959946667150639794667015087019625940457807714424391721682722368060",
        "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
        "0x42c89c774a08dc04b3dd201932bc8a5ea5f8b89bbb2a7e667aff81cd",
    ),
];

/// (k, xin, yin, xout, yout)
const P256_MULT_TESTS: [(&str, &str, &str, &str, &str);2] = [
    (
        "0x2a265f8bcbdcaf94d58519141e578124cb40d64a501fba9c11847b28965bc737",
        "0x023819813ac969847059028ea88a1f30dfbcde03fc791d3a252c6b41211882ea",
        "0xf93e4ae433cc12cf2a43fc0ef26400c0e125508224cdb649380f25479148a4ad",
        "0x4d4de80f1534850d261075997e3049321a0864082d24a917863366c0724f5ae3",
        "0xa22d2b7f7818a3563e0f7a76c9bf0921ac55e06e2e4d11795b233824b1db8cc0",
    ),
    (
        "0x313f72ff9fe811bf573176231b286a3bdb6f1b14e05c40146590727a71c3bccd",
        "0xcc11887b2d66cbae8f4d306627192522932146b42f01d3c6f92bd5c8ba739b06",
        "0xa2f08a029cd06b46183085bae9248b0ed15b70280c7ef13a457f5af382426031",
        "0x831c3f6b5f762d2f461901577af41354ac5f228c2591f84f8a6e51e2e3f17991",
        "0x93f90934cd0ef2c698cc471c60a93524e87ab31ca2412252337f364513e43684",
    ),
];

#[test]
fn elliptic_p224_base_mult() {
    let p224 = CurveP224::new().unwrap();
    
    for (i, e) in P224_BASE_MULT_TESTS.iter().enumerate() {
        let k = Nat::from_str(e.0).unwrap();
        
        let (x, y) = p224.scalar_base_point(&k);
        let (xs, ys) = (format!("{:#x}", x), format!("{:#x}", y));
        assert_eq!(xs.as_str(), e.1, "case-{}: {}", i, e.0);
        assert_eq!(ys.as_str(), e.2, "case-{}: {}", i, e.0);
        
        let cp = p224.curve_params();
        let (x0, y0) = cp.scalar_base_point(&k);
        assert_eq!(x0, x, "case-{}: {}", i, e.0);
        assert_eq!(y0, y, "case-{}: {}", i, e.0);
    }
}

#[test]
fn elliptic_p256_base_mult() {
    let p256 = CurveP256::new().unwrap();
    let mut scalars = Vec::with_capacity(P224_BASE_MULT_TESTS.len() + 1);
    P224_BASE_MULT_TESTS.iter().for_each(|e| {
        let k = Nat::from_str(e.0).unwrap();
        scalars.push(k);
    });
    let mut k = Nat::from(1u32);
    k <<= 500;
    scalars.push(k);
    
    for (i, k) in scalars.iter().enumerate().skip(21) {
        let (x, y) = p256.scalar_base_point(k);
        let (x2, y2) = p256.curve_params().scalar_base_point(k);
        assert_eq!(x, x2, "case-{}: {}", i, k);
        assert_eq!(y, y2, "case-{}: {}", i, k);
    }
}

#[test]
fn elliptic_p256_mult() {
    let p256 = CurveP256::new().unwrap();
    for (i, e) in P224_BASE_MULT_TESTS.iter().enumerate() {
        let (k, x, y) = (Nat::from_str(e.0).unwrap(), BigInt::from_str(e.1).unwrap(), BigInt::from_str(e.2).unwrap());
        let (xx, yy) = p256.scalar(&x, &y, &k);
        let (xx2, yy2) = p256.curve_params().scalar(&x, &y, &k);
        assert_eq!(xx, xx2, "case-{}: {}", i, k);
        assert_eq!(yy, yy2, "case-{}: {}", i, k);
    }
    
    for (i, e) in P256_MULT_TESTS.iter().enumerate() {
        let (k, x, y) = (Nat::from_str(e.0).unwrap(), BigInt::from_str(e.1).unwrap(), BigInt::from_str(e.2).unwrap());
        let (xout, yout) = (BigInt::from_str(e.3).unwrap(), BigInt::from_str(e.4).unwrap());
        
        let (xx, yy) = p256.scalar(&x, &y, &k);
        assert_eq!(xx, xout, "case-{}: {}", i, e.0);
        assert_eq!(yy, yout, "case-{}: {}", i, e.0);
    }
}

#[test]
fn elliptic_infinity() {
    let f: [Box<dyn EllipticCurve>; 2] = [
        Box::new(CurveP256::new().unwrap()),
        Box::new(CurveP224::new().unwrap())
    ];
    
    let (zx, zy, zk) = (BigInt::from(0u32), BigInt::from(0u32), Nat::from(0u32));
    for (i, curve) in f.iter().enumerate() {
        let (x, y) = curve.scalar_base_point(&zk);
        assert_eq!(x, zx, "case-{}", i);
        assert_eq!(y, zy, "case-{}", i);
        
        let (x2, y2) = curve.double(&zx, &zy);
        assert_eq!(x2, zx, "case-{}", i);
        assert_eq!(y2, zy, "case-{}", i);
        
        let (bx, by) = (curve.curve_params().base_point().0, curve.curve_params().base_point().1);
        let (x3, y3) = curve.add(bx, by, &zx, &zy);
        assert_eq!(&x3, bx, "case-{}", i);
        assert_eq!(&y3, by, "case-{}", i);
        
        let (x4, y4) = curve.add(&zx, &zy, bx, by);
        assert_eq!(&x4, bx, "case-{}", i);
        assert_eq!(&y4, by, "case-{}", i);
    }
}

#[test]
fn elliptic_combined_mult() {
    let p256 = CurveP256::new().unwrap();
    
    let combine_mult = |cp: &CurveP256, x: &BigInt, y: &BigInt, bs: &Nat, s: &Nat| {
        let (x1, y1) = cp.scalar_base_point(bs);
        let (x2, y2) = cp.scalar(x, y, s);
        cp.add(&x1, &y1, &x2, &y2)
    };
    
    let bzero = BigInt::from(0u32);
    let (zero, one, two) = (Nat::from(0u32), Nat::from(1u32), Nat::from(2u32));
    let (gx, gy) = (p256.curve_params().base_point().0.clone(), p256.curve_params().base_point().1.clone());

    // 0×G + 0×G = ∞
    let (x, y) = combine_mult(&p256, &gx, &gy, &zero, &zero);
    assert_eq!(x, bzero, "0×G + 0×G = ({}, {}), should be ∞", x, y);
    assert_eq!(y, bzero, "0×G + 0×G = ({}, {}), should be ∞", x, y);

    // 1×G + 0×G = G
    let (x, y) = combine_mult(&p256, &gx, &gy, &one, &zero);
    assert_eq!(x, gx, "1×G + 0×G = ({}, {}), should be ({}, {})", x, y, gx, gy);
    assert_eq!(y, gy, "1×G + 0×G = ({}, {}), should be ({}, {})", x, y, gx, gy);

    // 0×G + 1×G = G
    let (x, y) = combine_mult(&p256, &gx, &gy, &zero, &one);
    assert_eq!(x, gx, "0×G + 1×G = ({}, {}), should be ({}, {})", x, y, gx, gy);
    assert_eq!(y, gy, "0×G + 1×G = ({}, {}), should be ({}, {})", x, y, gx, gy);

    // 1×G + 1×G = 2×G
    let (x, y) = combine_mult(&p256, &gx, &gy, &one, &one);
    let (ggx, ggy) = p256.scalar_base_point(&two);
    assert_eq!(x, ggx, "1×G + 1×G = ({}, {}), should be ({}, {})", x, y, ggx, ggy);
    assert_eq!(y, ggy, "1×G + 1×G = ({}, {}), should be ({}, {})", x, y, ggx, ggy);

    // 1×G + (-1)×G = ∞
    let minusone = p256.curve_params().base_point_order().as_ref().clone() - 1u32;
    let (x, y) = combine_mult(&p256, &gx, &gy, &one, &minusone);
    assert_eq!(x, bzero, "1×G + (-1)×G = ({}, {}), should be ∞", x, y);
    assert_eq!(y, bzero, "1×G + (-1)×G = ({}, {}), should be ∞", x, y);
}
