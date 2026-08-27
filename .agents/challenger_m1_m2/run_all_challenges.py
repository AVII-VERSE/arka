"""
Empirical Test Runner for M1 & M2 Adversarial Challenge.
Executes all test methods directly and logs comprehensive results.
"""

import os
import sys
import traceback
import tempfile
import pathlib

# Add backend and agent to sys.path
repo_root = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(repo_root / "backend"))
sys.path.insert(0, str(repo_root / "agent"))

import test_m1_models_schemas_challenge as m1_tests
import test_m2_rootcheck_challenge as m2_tests


def run_test_class(test_cls, fixture_tmp_path=None):
    instance = test_cls()
    passed = 0
    failed = 0
    errors = []

    for attr in dir(instance):
        if attr.startswith("test_"):
            test_func = getattr(instance, attr)
            print(f"  [RUNNING] {test_cls.__name__}.{attr} ... ", end="")
            try:
                # Check if function takes tmp_path argument
                import inspect
                sig = inspect.signature(test_func)
                if "tmp_path" in sig.parameters:
                    with tempfile.TemporaryDirectory() as td:
                        test_func(tmp_path=pathlib.Path(td))
                else:
                    test_func()
                print("PASSED")
                passed += 1
            except Exception as e:
                print(f"FAILED: {e}")
                failed += 1
                errors.append((f"{test_cls.__name__}.{attr}", traceback.format_exc()))

    return passed, failed, errors


def main():
    print("=" * 70)
    print("ARKA SIEM/XDR — EMPIRICAL ADVERSARIAL CHALLENGE RUNNER")
    print("Target: Milestone 1 (Models & Schemas) & Milestone 2 (Rootcheck)")
    print("=" * 70)

    total_passed = 0
    total_failed = 0
    all_errors = []

    m1_classes = [
        m1_tests.TestEnumBoundaries,
        m1_tests.TestSchemaValidationAndMalformedInputs,
        m1_tests.TestORMModelInstantiationAndMapping,
    ]

    m2_classes = [
        m2_tests.TestRootcheckSuspiciousFiles,
        m2_tests.TestRootcheckHiddenProcesses,
        m2_tests.TestRootcheckListeningSocketsAndInterfaces,
        m2_tests.TestRootcheckSystemBinariesAndPreload,
        m2_tests.TestRootcheckCollectorLifecycle,
    ]

    print("\n--- Testing Milestone 1: Core DB Models & Schemas ---")
    for cls in m1_classes:
        p, f, errs = run_test_class(cls)
        total_passed += p
        total_failed += f
        all_errors.extend(errs)

    print("\n--- Testing Milestone 2: RootcheckScanner ---")
    for cls in m2_classes:
        p, f, errs = run_test_class(cls)
        total_passed += p
        total_failed += f
        all_errors.extend(errs)

    print("\n" + "=" * 70)
    print(f"SUMMARY: {total_passed} PASSED, {total_failed} FAILED (Total: {total_passed + total_failed})")
    print("=" * 70)

    if all_errors:
        print("\nFAILURE DETAILS:")
        for name, tb in all_errors:
            print(f"\n--- {name} ---")
            print(tb)

    return total_failed


if __name__ == "__main__":
    sys.exit(main())
