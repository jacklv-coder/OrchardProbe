use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::path::Path;

use orchardprobe_core::lab002::parse_fixed_sections;

const PRODUCTS_ROOT_ENV: &str = "ORCHARDPROBE_LAB002_PRODUCTS_ROOT";
const ROLE_PATHS: [&str; 3] = [
    "DemoLab.app/DemoLab",
    "DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework",
    "DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension",
];
const EXPECTED_SLICES: [(i32, i32); 2] = [(0x0100_0007, 3), (0x0100_000c, 0)];

#[test]
fn simulator_products_have_frozen_lab002_sections() {
    let Some(products_root) = env::var_os(PRODUCTS_ROOT_ENV) else {
        eprintln!("{PRODUCTS_ROOT_ENV} is unset; fixture-product verification is CI-only");
        return;
    };
    let products_root = Path::new(&products_root);

    for configuration in ["Debug", "Release"] {
        let configuration_root = products_root.join(format!("{configuration}-iphonesimulator"));
        let mut hashes = HashSet::new();
        for role_path in ROLE_PATHS {
            let binary = configuration_root.join(role_path);
            let mut file = File::open(&binary)
                .unwrap_or_else(|error| panic!("open '{}': {error}", binary.display()));
            let report = parse_fixed_sections(&mut file)
                .unwrap_or_else(|error| panic!("inspect '{}': {error}", binary.display()));
            let observed_slices: Vec<_> = report
                .slices
                .iter()
                .map(|slice| (slice.cpu_type, slice.cpu_subtype))
                .collect();
            assert_eq!(
                observed_slices,
                EXPECTED_SLICES,
                "unexpected slice inventory for '{}'",
                binary.display()
            );
            for slice in report.slices {
                assert_eq!(slice.section_length, 256);
                assert!(slice.section_slice_offset < slice.slice_file_size);
                assert_eq!(
                    slice.section_file_offset,
                    slice.slice_file_offset + slice.section_slice_offset
                );
                assert!(slice.encryption.is_none());
                assert!(
                    hashes.insert(slice.section_sha256),
                    "duplicate role/slice section hash in {configuration}"
                );
            }
        }
        assert_eq!(
            hashes.len(),
            ROLE_PATHS.len() * EXPECTED_SLICES.len(),
            "incomplete role/slice hash inventory in {configuration}"
        );
    }
}
