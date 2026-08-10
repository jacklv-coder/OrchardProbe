# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "tmpdir"

require_relative "../lib/lab004_operator_boundary"

class Lab004OperatorBoundaryTest < Minitest::Test
  Boundary = OrchardProbe::Lab004OperatorBoundary
  Layout = OrchardProbe::Lab003Layout
  Error = OrchardProbe::Lab004OperatorBoundary::Error
  EXPERIMENT = "4" * 64

  def setup
    @temporary = Dir.mktmpdir("orchardprobe-lab004-test-")
    @container = File.realpath(@temporary)
    File.chmod(0o700, @container)
  end

  def teardown
    FileUtils.remove_entry(@temporary) if File.exist?(@temporary)
  end

  def test_every_fixed_operation_profile_passes_device_free_preflight
    Boundary::PROFILES.each do |operation, profile|
      root = fresh_layout(operation)
      create_experiment(root, profile.before_lifecycle) if profile.before_lifecycle
      input_name = create_input(root, profile.input_kind)

      result = Boundary.preflight(
        root,
        operation: operation,
        experiment_name: profile.before_lifecycle && EXPERIMENT,
        external_input_name: input_name,
        diagnostic_name: "#{operation}.log",
        repository_root: repository_root
      )

      assert_equal "ready", result.fetch("status")
      assert_equal operation, result.fetch("operation")
      assert_equal "diagnostics", result.fetch("diagnostic_role")
      refute_includes result.inspect, root
      refute File.exist?(File.join(root, "diagnostics", "#{operation}.log"))
    end
  end

  def test_every_fixed_transition_closes_with_held_role_bindings
    Boundary::PROFILES.each do |operation, profile|
      root = fresh_layout("transition-#{operation}")
      create_experiment(root, profile.before_lifecycle) if profile.before_lifecycle
      input_name = create_input(root, profile.input_kind)
      observed_boundary = nil

      result = Boundary.with_operation(
        root,
        operation: operation,
        experiment_name: profile.before_lifecycle && EXPERIMENT,
        external_input_name: input_name,
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do |boundary|
        observed_boundary = boundary
        assert boundary.active?
        assert_helper_binding(boundary, operation)
        if profile.input_kind
          assert_equal "synthetic-#{profile.input_kind}",
                       Boundary.read_external_input(boundary)
        end
        advance_transition(root, profile)
        capture_transition(boundary)
        Boundary.publish_diagnostic(boundary, "helper-success")
        { "experiment_id" => EXPERIMENT }
      end

      assert_equal "closed", result.fetch("status")
      assert_equal operation, result.fetch("operation")
      refute observed_boundary.active?
      assert_equal 0o400,
                   File.stat(File.join(root, "diagnostics", "operation.log")).mode & 0o777
    end
  end

  def test_preflight_failure_never_enters_the_operation_callback
    root = fresh_layout("bad-preflight")
    called = false
    error = assert_boundary_error("experiment_required") do
      Boundary.with_operation(
        root,
        operation: "operator-close-enrollment",
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do
        called = true
      end
    end
    refute called
    refute_includes error.message, root
  end

  def test_preflight_reserves_aggregate_capacity_for_the_largest_diagnostic
    root = fresh_layout("diagnostic-byte-reservation")
    diagnostic_root = File.join(root, "diagnostics")
    reserved = Boundary::MAX_DIAGNOSTIC_MESSAGE_BYTES
    sizes = [
      Layout::MAX_DIAGNOSTIC_FILE_BYTES,
      Layout::MAX_DIAGNOSTIC_FILE_BYTES,
      Layout::MAX_DIAGNOSTIC_FILE_BYTES,
      Layout::MAX_DIAGNOSTIC_FILE_BYTES - reserved + 1,
    ]
    sizes.each_with_index do |size, index|
      write_private(
        File.join(diagnostic_root, "retained-#{index}.log"),
        "x" * size,
        0o400
      )
    end

    error = assert_boundary_error("diagnostic_total") do
      Boundary.preflight(
        root,
        operation: "operator-start-enrollment",
        diagnostic_name: "operation.log",
        repository_root: repository_root
      )
    end

    refute_includes error.message, root
    refute File.exist?(File.join(diagnostic_root, "operation.log"))
  end

  def test_success_requires_the_exact_post_operation_lifecycle
    root = fresh_layout("missing-transition")
    create_experiment(root, "base")
    create_input(root, "receipt")

    error = assert_boundary_error("operation_failed") do
      Boundary.with_operation(
        root,
        operation: "operator-close-enrollment",
        experiment_name: EXPERIMENT,
        external_input_name: "receipt.json",
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do |boundary|
        capture_transition(boundary)
        { "experiment_id" => EXPERIMENT }
      end
    end
    refute_includes error.message, root
    refute_includes error.message, EXPERIMENT
  end

  def test_success_requires_a_bounded_diagnostic_in_its_role
    root = fresh_layout("missing-diagnostic")

    assert_boundary_error("closure_failed") do
      Boundary.with_operation(
        root,
        operation: "operator-start-enrollment",
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do |boundary|
        create_experiment(root, "base")
        capture_transition(boundary)
        { "experiment_id" => EXPERIMENT }
      end
    end
  end

  def test_external_input_identity_is_unchanged_at_closure
    root = fresh_layout("changed-input")
    create_experiment(root, "base")
    input = File.join(root, "external-inputs", "receipt.json")
    write_private(input, "synthetic-receipt", 0o600)
    displaced = File.join(@container, "displaced-receipt.json")

    assert_boundary_error("closure_failed") do
      Boundary.with_operation(
        root,
        operation: "operator-close-enrollment",
        experiment_name: EXPERIMENT,
        external_input_name: "receipt.json",
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do |boundary|
        advance_experiment(root, "base", "enrollment-closed")
        capture_transition(boundary)
        Boundary.publish_diagnostic(boundary, "helper-success")
        File.rename(input, displaced)
        write_private(input, "synthetic-receipt", 0o600)
        { "experiment_id" => EXPERIMENT }
      end
    end
  end

  def test_external_input_content_is_unchanged_when_metadata_is_preserved
    root = fresh_layout("changed-input-content")
    create_experiment(root, "base")
    input = File.join(root, "external-inputs", "receipt.json")
    write_private(input, "synthetic-receipt", 0o600)
    fixed_time = Time.at(1_700_000_000)
    File.utime(fixed_time, fixed_time, input)
    original = File.stat(input)

    assert_boundary_error("closure_failed") do
      Boundary.with_operation(
        root,
        operation: "operator-close-enrollment",
        experiment_name: EXPERIMENT,
        external_input_name: "receipt.json",
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do |boundary|
        advance_experiment(root, "base", "enrollment-closed")
        capture_transition(boundary)
        Boundary.publish_diagnostic(boundary, "helper-success")
        File.open(input, "r+b") do |file|
          file.write("malicious-receipt")
          file.flush
          file.fsync
        end
        File.utime(original.atime, original.mtime, input)
        changed = File.stat(input)
        assert_equal original.ino, changed.ino
        assert_equal original.size, changed.size
        assert_equal original.mode, changed.mode
        assert_equal original.mtime.to_f, changed.mtime.to_f
        { "experiment_id" => EXPERIMENT }
      end
    end
  end

  def test_callback_failure_is_sanitized_when_the_prestate_closes_cleanly
    root = fresh_layout("callback-failure")
    create_experiment(root, "enrollment-closed")
    expected = Class.new(StandardError)

    error = assert_boundary_error("operation_failed") do
      Boundary.with_operation(
        root,
        operation: "operator-start-run-1",
        experiment_name: EXPERIMENT,
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do
        raise expected, "synthetic callback failure"
      end
    end
    refute_includes error.message, "synthetic callback failure"
    refute File.exist?(File.join(root, "diagnostics", "operation.log"))
  end

  def test_callback_failure_removes_the_boundary_diagnostic
    root = fresh_layout("callback-failure-diagnostic")
    create_experiment(root, "enrollment-closed")

    assert_boundary_error("operation_failed") do
      Boundary.with_operation(
        root,
        operation: "operator-start-run-1",
        experiment_name: EXPERIMENT,
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do |boundary|
        Boundary.publish_diagnostic(boundary, "helper-failure")
        raise "private callback failure"
      end
    end
    refute File.exist?(File.join(root, "diagnostics", "operation.log"))
  end

  def test_post_write_validation_failure_removes_the_unrecorded_diagnostic
    root = fresh_layout("post-write-diagnostic-failure")
    original = Layout.method(:validate_diagnostics_role!)
    inject = false
    calls = 0
    Layout.define_singleton_method(:validate_diagnostics_role!) do |*args, **kwargs|
      result = original.call(*args, **kwargs)
      if inject
        calls += 1
        if calls == 2
          inject = false
          raise Layout::Error.new(
            "synthetic_post_write",
            "LAB-003 synthetic post-write validation failure"
          )
        end
      end
      result
    end

    begin
      assert_boundary_error("closure_failed") do
        Boundary.with_operation(
          root,
          operation: "operator-start-enrollment",
          diagnostic_name: "operation.log",
          repository_root: repository_root
        ) do |boundary|
          create_experiment(root, "base")
          capture_transition(boundary)
          inject = true
          Boundary.publish_diagnostic(boundary, "helper-success")
        end
      end
      refute File.exist?(File.join(root, "diagnostics", "operation.log"))
    ensure
      Layout.define_singleton_method(:validate_diagnostics_role!, original)
    end
  end

  def test_success_rejects_replaced_or_additional_diagnostics
    ["replace", "additional"].each do |mutation|
      root = fresh_layout("diagnostic-#{mutation}")
      displaced = File.join(@container, "#{mutation}-displaced.log")

      assert_boundary_error("closure_failed") do
        Boundary.with_operation(
          root,
          operation: "operator-start-enrollment",
          diagnostic_name: "operation.log",
          repository_root: repository_root
        ) do |boundary|
          create_experiment(root, "base")
          capture_transition(boundary)
          Boundary.publish_diagnostic(boundary, "helper-success")
          if mutation == "replace"
            path = File.join(root, "diagnostics", "operation.log")
            File.rename(path, displaced)
            write_private(
              path,
              Boundary::DIAGNOSTIC_MESSAGES.fetch("helper-success"),
              0o400
            )
          else
            write_private(
              File.join(root, "diagnostics", "unrelated.log"),
              "unrelated",
              0o400
            )
          end
          { "experiment_id" => EXPERIMENT }
        end
      end
    end
  end

  def test_closure_rejects_in_place_change_to_retained_diagnostic
    root = fresh_layout("retained-diagnostic-content")
    retained = write_private(
      File.join(root, "diagnostics", "retained.log"),
      "retained evidence",
      0o400
    )
    fixed_time = Time.at(1_700_000_000)
    File.utime(fixed_time, fixed_time, retained)
    original = File.stat(retained)

    assert_boundary_error("closure_failed") do
      Boundary.with_operation(
        root,
        operation: "operator-start-enrollment",
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do |boundary|
        assert_exclusive_lock_is_held(retained)
        create_experiment(root, "base")
        capture_transition(boundary)
        Boundary.publish_diagnostic(boundary, "helper-success")
        assert_exclusive_lock_is_held(
          File.join(root, "diagnostics", "operation.log")
        )
        assert_shared_lock_is_held(
          File.join(root, "diagnostics", "operation.log")
        )
        rewrite_preserving_metadata(retained, "x" * original.size, original)
        { "experiment_id" => EXPERIMENT }
      end
    end
  end

  def test_callback_failure_with_partial_publication_becomes_generic_closure_failure
    root = fresh_layout("partial-callback-failure")
    create_experiment(root, "enrollment-closed")

    error = assert_boundary_error("closure_failed") do
      Boundary.with_operation(
        root,
        operation: "operator-start-run-1",
        experiment_name: EXPERIMENT,
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do
        advance_experiment(root, "enrollment-closed", "run-1-control")
        raise "private callback detail"
      end
    end
    refute_includes error.message, "private callback detail"
  end

  def test_wrong_role_input_and_existing_diagnostic_fail_before_callback
    root = fresh_layout("wrong-role")
    create_experiment(root, "base")
    write_private(
      File.join(root, "experiments", EXPERIMENT, "receipt.json"),
      "private receipt",
      0o400
    )
    write_private(File.join(root, "diagnostics", "operation.log"), "", 0o400)

    assert_boundary_error do
      Boundary.preflight(
        root,
        operation: "operator-close-enrollment",
        experiment_name: EXPERIMENT,
        external_input_name: "receipt.json",
        diagnostic_name: "operation.log",
        repository_root: repository_root
      )
    end
  end

  def test_helper_binding_must_be_the_held_experiment_role
    root = fresh_layout("helper-binding")
    create_experiment(root, "run-1-control")
    create_input(root, "export")
    other = fresh_layout("other-helper-binding")

    Boundary.with_operation(
      root,
      operation: "operator-close-run-1",
      experiment_name: EXPERIMENT,
      external_input_name: "export.json",
      diagnostic_name: "operation.log",
      repository_root: repository_root
    ) do |boundary|
      other_handle = File.open(File.join(other, "experiments"), File::RDONLY)
      stat = other_handle.stat
      begin
        assert_boundary_error("helper_binding") do
          Boundary.authorize_helper_bindings!(
            boundary,
            operation: "operator-close-run",
            bindings: [{ handle: other_handle, identity: [stat.dev, stat.ino] }],
            input: "synthetic-export"
          )
        end
      ensure
        other_handle.close
      end
      advance_experiment(root, "run-1-control", "run-1-closed")
      capture_transition(boundary)
      Boundary.publish_diagnostic(boundary, "helper-success")
      { "experiment_id" => EXPERIMENT }
    end
  end

  def test_helper_rejects_an_extra_unheld_directory_binding
    root = fresh_layout("extra-helper-binding")
    other = fresh_layout("extra-helper-binding-other")

    Boundary.with_operation(
      root,
      operation: "operator-start-enrollment",
      diagnostic_name: "operation.log",
      repository_root: repository_root
    ) do |boundary|
      primary = boundary.primary_directory
      primary_stat = primary.handle.stat
      other_handle = File.open(File.join(other, "experiments"), File::RDONLY)
      other_stat = other_handle.stat
      begin
        assert_boundary_error("helper_scope") do
          Boundary.authorize_helper_bindings!(
            boundary,
            operation: "operator-start-enrollment",
            bindings: [
              {
                handle: primary.handle,
                identity: [primary_stat.dev, primary_stat.ino],
              },
              {
                handle: other_handle,
                identity: [other_stat.dev, other_stat.ino],
              },
            ],
            input: "{}"
          )
        end
      ensure
        other_handle.close
      end
      create_experiment(root, "base")
      capture_transition(boundary)
      Boundary.publish_diagnostic(boundary, "helper-success")
      { "experiment_id" => EXPERIMENT }
    end
  end

  def test_helper_authorization_rechecks_exact_role_inventories
    root = fresh_layout("helper-inventory-recheck")
    create_experiment(root, "enrollment-closed")
    unexpected = File.join(root, "external-inputs", "unexpected.json")

    Boundary.with_operation(
      root,
      operation: "operator-start-run-1",
      experiment_name: EXPERIMENT,
      diagnostic_name: "operation.log",
      repository_root: repository_root
    ) do |boundary|
      write_private(unexpected, "unexpected", 0o600)
      object = boundary.primary_directory
      stat = object.handle.stat
      assert_boundary_error("input_inventory") do
        Boundary.authorize_helper_bindings!(
          boundary,
          operation: "operator-start-run",
          bindings: [{ handle: object.handle, identity: [stat.dev, stat.ino] }],
          input: "{}"
        )
      end
      File.unlink(unexpected)
      assert_helper_binding(boundary, "operator-start-run-1")
      advance_experiment(root, "enrollment-closed", "run-1-control")
      capture_transition(boundary)
      Boundary.publish_diagnostic(boundary, "helper-success")
      { "experiment_id" => EXPERIMENT }
    end
  end

  def test_closure_rejects_external_input_added_after_transition_capture
    root = fresh_layout("closure-external-input-inventory")

    assert_boundary_error("closure_failed") do
      Boundary.with_operation(
        root,
        operation: "operator-start-enrollment",
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do |boundary|
        create_experiment(root, "base")
        capture_transition(boundary)
        write_private(
          File.join(root, "external-inputs", "unexpected.json"),
          "unexpected",
          0o600
        )
        Boundary.publish_diagnostic(boundary, "helper-success")
        { "experiment_id" => EXPERIMENT }
      end
    end
  end

  def test_preflight_sanitizes_layout_syscall_failure
    root = fresh_layout("preflight-syscall")
    File.chmod(0o000, root)

    error = assert_boundary_error("boundary_open") do
      Boundary.preflight(
        root,
        operation: "operator-start-enrollment",
        diagnostic_name: "operation.log",
        repository_root: repository_root
      )
    end
    refute_includes error.message, root
  ensure
    File.chmod(0o700, root) if root && File.exist?(root)
  end

  def test_helper_authorization_rejects_a_substituted_held_control
    root = fresh_layout("helper-control-recheck")
    experiment = create_experiment(root, "enrollment-closed")
    control = File.join(experiment, Layout::BASE_CONTROL_NAMES.first)
    displaced = File.join(@container, "displaced-control")

    assert_boundary_error("closure_failed") do
      Boundary.with_operation(
        root,
        operation: "operator-start-run-1",
        experiment_name: EXPERIMENT,
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do |boundary|
        File.rename(control, displaced)
        write_private(control, "substituted", 0o400)
        object = boundary.primary_directory
        stat = object.handle.stat
        assert_boundary_error("protocol_identity") do
          Boundary.authorize_helper_bindings!(
            boundary,
            operation: "operator-start-run",
            bindings: [{ handle: object.handle, identity: [stat.dev, stat.ino] }],
            input: "{}"
          )
        end
        raise "stop after rejected helper authorization"
      end
    end
  end

  def test_helper_authorization_rejects_in_place_protocol_content_change
    root = fresh_layout("helper-control-content-recheck")
    experiment = create_experiment(root, "enrollment-closed")
    control = File.join(experiment, Layout::BASE_CONTROL_NAMES.first)
    fixed_time = Time.at(1_700_000_000)
    File.utime(fixed_time, fixed_time, control)
    original = File.stat(control)

    assert_boundary_error("closure_failed") do
      Boundary.with_operation(
        root,
        operation: "operator-start-run-1",
        experiment_name: EXPERIMENT,
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do |boundary|
        rewrite_preserving_metadata(control, "x" * original.size, original)
        object = boundary.primary_directory
        stat = object.handle.stat
        assert_boundary_error("protocol_content") do
          Boundary.authorize_helper_bindings!(
            boundary,
            operation: "operator-start-run",
            bindings: [{ handle: object.handle, identity: [stat.dev, stat.ino] }],
            input: "{}"
          )
        end
        raise "stop after rejected helper authorization"
      end
    end
  end

  def test_protocol_artifact_locks_are_held_through_transition_and_closure
    root = fresh_layout("protocol-locks")
    experiment = create_experiment(root, "enrollment-closed")
    control = File.join(experiment, Layout::BASE_CONTROL_NAMES.first)

    result = Boundary.with_operation(
      root,
      operation: "operator-start-run-1",
      experiment_name: EXPERIMENT,
      diagnostic_name: "operation.log",
      repository_root: repository_root
    ) do |boundary|
      assert_exclusive_lock_is_held(control)
      assert_helper_binding(boundary, "operator-start-run-1")
      advance_experiment(root, "enrollment-closed", "run-1-control")
      capture_transition(boundary)
      artifact = File.join(
        experiment,
        "run-1-control",
        Layout::PHASE_INVENTORIES.fetch("run-1-control").first
      )
      assert_exclusive_lock_is_held(artifact)
      Boundary.publish_diagnostic(boundary, "helper-success")
      { "experiment_id" => EXPERIMENT }
    end

    assert_equal "closed", result.fetch("status")
  end

  def test_failed_transition_capture_releases_new_protocol_locks
    root = fresh_layout("failed-transition-locks")
    experiment = create_experiment(root, "enrollment-closed")

    assert_boundary_error("operation_failed") do
      Boundary.with_operation(
        root,
        operation: "operator-start-run-1",
        experiment_name: EXPERIMENT,
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do |boundary|
        advance_experiment(root, "enrollment-closed", "run-1-control")
        paths = Layout::PHASE_INVENTORIES.fetch("run-1-control").map do |name|
          File.join(experiment, "run-1-control", name)
        end
        with_writable_handle(paths.last) do |blocked|
          assert blocked.flock(File::LOCK_EX | File::LOCK_NB)
          assert_boundary_error("protocol_lock") { capture_transition(boundary) }
          with_writable_handle(paths.first) do |probe|
            assert probe.flock(File::LOCK_EX | File::LOCK_NB)
          end
        end
        FileUtils.remove_entry(File.join(experiment, "run-1-control"))
        raise "stop after rejected transition capture"
      end
    end
  end

  def test_closure_rejects_replacement_of_captured_transition_descendants
    ["new-experiment", "existing-control"].each do |mutation|
      root = fresh_layout("captured-#{mutation}")
      before = mutation == "new-experiment" ? nil : "enrollment-closed"
      create_experiment(root, before) if before

      assert_boundary_error("closure_failed") do
        Boundary.with_operation(
          root,
          operation: before ? "operator-start-run-1" : "operator-start-enrollment",
          experiment_name: before && EXPERIMENT,
          diagnostic_name: "operation.log",
          repository_root: repository_root
        ) do |boundary|
          if before
            advance_experiment(root, before, "run-1-control")
          else
            create_experiment(root, "base")
          end
          capture_transition(boundary)
          experiment = File.join(root, "experiments", EXPERIMENT)
          if mutation == "new-experiment"
            File.rename(experiment, File.join(@container, "captured-original"))
            create_experiment(root, "base")
          else
            control = File.join(experiment, Layout::BASE_CONTROL_NAMES.first)
            File.rename(control, File.join(@container, "captured-control"))
            write_private(control, "substituted", 0o400)
          end
          Boundary.publish_diagnostic(boundary, "helper-success")
          { "experiment_id" => EXPERIMENT }
        end
      end
    end
  end

  def test_closure_rejects_in_place_change_to_captured_protocol_content
    root = fresh_layout("captured-content")
    create_experiment(root, "enrollment-closed")

    assert_boundary_error("closure_failed") do
      Boundary.with_operation(
        root,
        operation: "operator-start-run-1",
        experiment_name: EXPERIMENT,
        diagnostic_name: "operation.log",
        repository_root: repository_root
      ) do |boundary|
        advance_experiment(root, "enrollment-closed", "run-1-control")
        artifact = File.join(
          root,
          "experiments",
          EXPERIMENT,
          "run-1-control",
          Layout::PHASE_INVENTORIES.fetch("run-1-control").first
        )
        fixed_time = Time.at(1_700_000_000)
        File.utime(fixed_time, fixed_time, artifact)
        original = File.stat(artifact)
        capture_transition(boundary)
        rewrite_preserving_metadata(artifact, "x" * original.size, original)
        Boundary.publish_diagnostic(boundary, "helper-success")
        { "experiment_id" => EXPERIMENT }
      end
    end
  end

  def test_operation_and_selection_are_closed
    root = fresh_layout("closed-selection")
    assert_boundary_error("operation_invalid") do
      Boundary.preflight(
        root,
        operation: "operator-arbitrary",
        diagnostic_name: "operation.log",
        repository_root: repository_root
      )
    end
    assert_boundary_error("experiment_forbidden") do
      Boundary.preflight(
        root,
        operation: "operator-start-enrollment",
        experiment_name: EXPERIMENT,
        diagnostic_name: "operation.log",
        repository_root: repository_root
      )
    end
    assert_boundary_error("input_forbidden") do
      Boundary.preflight(
        root,
        operation: "operator-start-enrollment",
        external_input_name: "receipt.json",
        diagnostic_name: "operation.log",
        repository_root: repository_root
      )
    end
  end

  private

  def repository_root
    File.expand_path("../..", __dir__)
  end

  def fresh_layout(name)
    root = File.join(@container, name)
    Layout.prepare(root, repository_root: repository_root)
    root
  end

  def write_private(path, content, mode)
    File.binwrite(path, content)
    File.chmod(mode, path)
    path
  end

  def rewrite_preserving_metadata(path, content, original)
    assert_equal original.size, content.bytesize
    File.chmod(0o600, path)
    File.open(path, "r+b") do |file|
      file.write(content)
      file.flush
      file.fsync
    end
    File.chmod(original.mode & 0o777, path)
    File.utime(original.atime, original.mtime, path)
    changed = File.stat(path)
    assert_equal original.ino, changed.ino
    assert_equal original.size, changed.size
    assert_equal original.mode, changed.mode
    assert_equal original.mtime.to_f, changed.mtime.to_f
  end

  def assert_exclusive_lock_is_held(path)
    with_writable_handle(path) do |file|
      refute file.flock(File::LOCK_EX | File::LOCK_NB)
    end
  end

  def assert_shared_lock_is_held(path)
    with_writable_handle(path) do |file|
      refute file.flock(File::LOCK_SH | File::LOCK_NB)
    end
  end

  def with_writable_handle(path)
    original_mode = File.stat(path).mode & 0o777
    File.chmod(original_mode | 0o200, path)
    File.open(path, File::RDWR | File::NONBLOCK) do |file|
      File.chmod(original_mode, path)
      yield file
    end
  ensure
    File.chmod(original_mode, path) if original_mode && File.exist?(path)
  end

  def create_experiment(root, lifecycle)
    experiment = File.join(root, "experiments", EXPERIMENT)
    Dir.mkdir(experiment, 0o700)
    Layout::BASE_CONTROL_NAMES.each do |name|
      write_private(File.join(experiment, name), "synthetic-#{name}", 0o400)
    end
    Layout::LIFECYCLE_PHASES.fetch(lifecycle).each do |phase|
      create_phase(experiment, phase)
    end
    experiment
  end

  def create_phase(experiment, phase)
    directory = File.join(experiment, phase)
    Dir.mkdir(directory, 0o700)
    Layout::PHASE_INVENTORIES.fetch(phase).each do |name|
      write_private(File.join(directory, name), "synthetic-#{name}", 0o400)
    end
  end

  def advance_transition(root, profile)
    if profile.before_lifecycle
      advance_experiment(root, profile.before_lifecycle, profile.after_lifecycle)
    else
      create_experiment(root, profile.after_lifecycle)
    end
  end

  def advance_experiment(root, before_lifecycle, after_lifecycle)
    experiment = File.join(root, "experiments", EXPERIMENT)
    before = Layout::LIFECYCLE_PHASES.fetch(before_lifecycle)
    after = Layout::LIFECYCLE_PHASES.fetch(after_lifecycle)
    (after - before).each { |phase| create_phase(experiment, phase) }
  end

  def create_input(root, kind)
    return nil unless kind

    name = kind == "receipt" ? "receipt.json" : "export.json"
    write_private(
      File.join(root, "external-inputs", name),
      "synthetic-#{kind}",
      0o600
    )
    name
  end

  def assert_helper_binding(boundary, boundary_operation)
    object = boundary.primary_directory
    stat = object.handle.stat
    helper_operation = Boundary::HELPER_OPERATIONS.fetch(boundary_operation)
    helper_input = case helper_operation
                   when "operator-close-enrollment"
                     "#{'f' * 64}\n#{Boundary.read_external_input(boundary)}"
                   when "operator-close-run"
                     Boundary.read_external_input(boundary)
                   else
                     "{}"
                   end
    if boundary.profile.input_kind
      assert_boundary_error("helper_input") do
        Boundary.authorize_helper_bindings!(
          boundary,
          operation: helper_operation,
          bindings: [{ handle: object.handle, identity: [stat.dev, stat.ino] }],
          input: "wrong-role-copy"
        )
      end
    end
    assert Boundary.authorize_helper_bindings!(
      boundary,
      operation: helper_operation,
      bindings: [{ handle: object.handle, identity: [stat.dev, stat.ino] }],
      input: helper_input
    )
  end

  def capture_transition(boundary)
    Boundary.capture_transition!(
      boundary,
      result: { "experiment_id" => EXPERIMENT }
    )
  end

  def assert_boundary_error(code = nil)
    error = assert_raises(Error) { yield }
    assert_equal code, error.code if code
    error
  end
end
