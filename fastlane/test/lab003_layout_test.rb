# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "rbconfig"
require "timeout"
require "tmpdir"

require_relative "../lib/lab003_layout"

class Lab003LayoutTest < Minitest::Test
  Layout = OrchardProbe::Lab003Layout
  Error = OrchardProbe::Lab003Layout::Error
  EXPERIMENT = "a" * 64

  def setup
    @temporary = Dir.mktmpdir("orchardprobe-lab003-test-")
    @container = File.realpath(@temporary)
    File.chmod(0o700, @container)
    @root = File.join(@container, "layout")
    Layout.prepare(@root, repository_root: repository_root)
  end

  def teardown
    FileUtils.remove_entry(@temporary) if File.exist?(@temporary)
  end

  def test_prepare_creates_only_the_three_sanitized_roles
    assert_equal Layout::ROLE_NAMES.sort, Dir.children(@root).sort
    Layout::ROLE_NAMES.each do |name|
      assert_equal 0o700, File.stat(File.join(@root, name)).mode & 0o777
    end
    result = Layout.preflight(@root, repository_root: repository_root)
    assert_equal({ "status" => "ready" }, result)
    refute_includes result.inspect, @root
  end

  def test_prepare_cleans_a_new_role_that_fails_validation
    failed_root = File.join(@container, "failed-layout")
    assert_layout_error("directory_identity") do
      Layout.prepare(
        failed_root,
        repository_root: repository_root,
        after_role_open: lambda do |name, opened|
          opened.handle.chmod(0o755) if name == "external-inputs"
        end
      )
    end
    refute File.exist?(failed_root)
  end

  def test_prepare_tracks_a_role_before_its_first_open
    failed_root = File.join(@container, "failed-before-open-layout")
    assert_layout_error("prepare_failed") do
      Layout.prepare(
        failed_root,
        repository_root: repository_root,
        after_role_create: lambda do |name, record|
          File.chmod(0o000, record.fetch(:path)) if name == "external-inputs"
        end
      )
    end
    refute File.exist?(failed_root)
  end

  def test_every_valid_lifecycle_inventory_is_accepted
    Layout::LIFECYCLE_PHASES.each_key do |lifecycle|
      root = fresh_layout("lifecycle-#{lifecycle}")
      create_experiment(root, lifecycle)
      result = Layout.preflight(
        root,
        repository_root: repository_root,
        experiment_name: EXPERIMENT,
        lifecycle: lifecycle
      )
      assert_equal "experiments/<opaque-id>", result.fetch("experiment_role")
    end
  end

  def test_extra_and_missing_experiment_entries_fail_closed
    experiment = create_experiment(@root, "base")
    write_private(File.join(experiment, "unexpected.json"), "extra", 0o400)
    assert_layout_error("inventory") { preflight_experiment("base") }

    File.unlink(File.join(experiment, "unexpected.json"))
    File.unlink(File.join(experiment, Layout::BASE_CONTROL_NAMES.first))
    assert_layout_error("inventory") { preflight_experiment("base") }
  end

  def test_private_root_inventory_is_exact
    write_private(File.join(@root, "unexpected"), "extra", 0o600)
    assert_layout_error("inventory") do
      Layout.preflight(@root, repository_root: repository_root)
    end
  end

  def test_inventory_revalidation_uses_the_requested_owner
    context = Layout.open_layout(@root, repository_root: repository_root)
    requested_uid = Process.uid + 1
    observed_uids = []
    original_validator = Layout.method(:revalidate_opened!)
    Layout.define_singleton_method(:revalidate_opened!) do |_opened, uid, **_options|
      observed_uids << uid
    end

    assert_empty Layout.entries(
      context.roles.fetch("diagnostics"),
      requested_uid
    )
    assert_equal [requested_uid, requested_uid], observed_uids
  ensure
    if original_validator
      Layout.define_singleton_method(:revalidate_opened!, original_validator)
    end
    context&.close
  end

  def test_a_future_phase_is_invalid_for_an_earlier_lifecycle
    create_experiment(@root, "run-1-control")
    assert_layout_error("inventory") { preflight_experiment("base") }
  end

  def test_unselected_experiments_must_be_empty
    experiment = create_experiment(@root, "base")
    write_private(File.join(experiment, "shell.log"), "diagnostic", 0o400)

    assert_layout_error("experiment_inventory") do
      Layout.preflight(@root, repository_root: repository_root)
    end
  end

  def test_only_the_selected_experiment_may_exist
    create_experiment(@root, "base")
    other = "b" * 64
    Dir.mkdir(File.join(@root, "experiments", other), 0o700)

    assert_layout_error("experiment_inventory") { preflight_experiment("base") }
  end

  def test_wrong_role_nesting_and_regular_file_substitution_are_rejected
    experiment = create_experiment(@root, "base")
    write_private(File.join(experiment, "receipt.json"), "receipt", 0o400)
    assert_layout_error("inventory") { preflight_experiment("base") }

    other = fresh_layout("regular-substitution")
    diagnostics = File.join(other, "diagnostics")
    Dir.rmdir(diagnostics)
    write_private(diagnostics, "not-a-directory", 0o700)
    assert_layout_error { Layout.preflight(other, repository_root: repository_root) }
  end

  def test_fifo_with_an_experiment_name_fails_without_blocking
    fifo = File.join(@root, "experiments", EXPERIMENT)
    assert system("/usr/bin/mkfifo", fifo)
    File.chmod(0o700, fifo)

    Timeout.timeout(2) do
      assert_layout_error("directory_identity") do
        Layout.preflight(
          @root,
          repository_root: repository_root,
          experiment_name: EXPERIMENT,
          lifecycle: "base"
        )
      end
    end
  end

  def test_inventory_pipe_is_drained_in_bounded_chunks
    names = 128.times.map { |index| "#{index}-#{'x' * 120}" }
    reader, writer = IO.pipe
    pid = fork do
      reader.close
      Marshal.dump(names, writer)
      writer.close
      exit! 0
    end
    writer.close
    payload = Layout.read_bounded_pipe(reader, Layout::MAX_INVENTORY_PAYLOAD_BYTES)
    reader.close
    _, status = Process.wait2(pid)

    assert status.success?
    assert_equal names, Marshal.load(payload)
  ensure
    reader&.close unless reader&.closed?
    writer&.close unless writer&.closed?
  end

  def test_symlinked_ancestor_overlap_and_symlinked_input_are_rejected
    real = File.join(@container, "real-diagnostics")
    Dir.mkdir(real, 0o700)
    FileUtils.remove_entry(File.join(@root, "diagnostics"))
    File.symlink(real, File.join(@root, "diagnostics"))
    assert_layout_error { Layout.preflight(@root, repository_root: repository_root) }

    other = fresh_layout("symlink-input")
    target = File.join(@container, "target.json")
    write_private(target, "receipt", 0o600)
    File.symlink(target, File.join(other, "external-inputs", "receipt.json"))
    assert_layout_error do
      Layout.preflight(
        other,
        repository_root: repository_root,
        external_input_name: "receipt.json",
        input_kind: "receipt"
      )
    end
  end

  def test_external_input_must_be_a_direct_child_name
    assert_layout_error("name_invalid") do
      Layout.preflight(
        @root,
        repository_root: repository_root,
        external_input_name: "nested/receipt.json",
        input_kind: "receipt"
      )
    end
  end

  def test_unsafe_permissions_and_input_maximum_plus_one_are_rejected
    input = File.join(@root, "external-inputs", "receipt.json")
    write_private(input, "receipt", 0o644)
    assert_layout_error("file_identity") { preflight_input }

    File.chmod(0o600, input)
    File.binwrite(input, "x" * (Layout::INPUT_LIMITS.fetch("receipt") + 1))
    assert_layout_error("file_identity") { preflight_input }
  end

  def test_external_input_at_the_exact_bound_is_accepted
    write_private(
      File.join(@root, "external-inputs", "receipt.json"),
      "x" * Layout::INPUT_LIMITS.fetch("receipt"),
      0o600
    )
    result = preflight_input
    assert_equal "external-inputs", result.fetch("input_role")
  end

  def test_external_input_role_rejects_multiple_valid_files
    external = File.join(@root, "external-inputs")
    write_private(File.join(external, "receipt.json"), "receipt", 0o600)
    write_private(File.join(external, "export.bin"), "export", 0o600)

    assert_layout_error("input_count") { preflight_input }
  end

  def test_changed_input_identity_between_checks_is_rejected
    input = File.join(@root, "external-inputs", "receipt.json")
    write_private(input, "receipt", 0o600)
    displaced = File.join(@container, "displaced.json")
    assert_layout_error("identity_changed") do
      Layout.preflight(
        @root,
        repository_root: repository_root,
        external_input_name: "receipt.json",
        input_kind: "receipt",
        before_second_check: lambda do
          File.rename(input, displaced)
          write_private(input, "receipt", 0o600)
        end
      )
    end
  end

  def test_reserved_diagnostic_identity_is_held_through_the_second_check
    diagnostics = File.join(@root, "diagnostics")
    existing = File.join(diagnostics, "existing.log")
    reserved = File.join(diagnostics, "reserved.log")
    displaced = File.join(@container, "displaced-reserved.log")
    write_private(existing, "diagnostic", 0o400)

    assert_layout_error("identity_changed") do
      Layout.preflight(
        @root,
        repository_root: repository_root,
        diagnostic_name: "reserved.log",
        before_second_check: lambda do
          directory_stat = File.stat(diagnostics)
          File.rename(reserved, displaced)
          File.link(existing, reserved)
          File.utime(directory_stat.atime, directory_stat.mtime, diagnostics)
        end
      )
    end
  end

  def test_role_replacement_after_layout_open_fails_closed
    experiment = create_experiment(@root, "base")
    control = File.join(experiment, Layout::BASE_CONTROL_NAMES.first)
    external = File.join(@root, "external-inputs")
    File.link(control, File.join(external, "receipt.json"))
    displaced = File.join(@container, "displaced-external-inputs")

    assert_layout_error("identity_changed") do
      Layout.preflight(
        @root,
        repository_root: repository_root,
        experiment_name: EXPERIMENT,
        lifecycle: "base",
        external_input_name: "receipt.json",
        input_kind: "receipt",
        after_layout_open: lambda do
          File.rename(external, displaced)
          Dir.mkdir(external, 0o700)
          write_private(File.join(external, "receipt.json"), "replacement", 0o600)
        end
      )
    end
  end

  def test_descriptor_relative_open_does_not_follow_a_replaced_role_path
    external = File.join(@root, "external-inputs")
    original = File.join(external, "receipt.json")
    write_private(original, "original", 0o600)
    context = Layout.open_layout(@root, repository_root: repository_root)
    displaced = File.join(@container, "held-external-inputs")
    begin
      File.rename(external, displaced)
      Dir.mkdir(external, 0o700)
      replacement = File.join(external, "receipt.json")
      write_private(replacement, "replacement", 0o600)
      assert_layout_error("file_identity") do
        Layout.open_regular_file_at!(
          context.roles.fetch("external-inputs"),
          "receipt.json",
          Process.uid,
          maximum_size: Layout::INPUT_LIMITS.fetch("receipt"),
          allow_empty: false
        )
      end
    ensure
      context.close
    end
  end

  def test_hard_link_alias_between_control_and_external_input_is_rejected
    experiment = create_experiment(@root, "base")
    control = File.join(experiment, Layout::BASE_CONTROL_NAMES.first)
    File.link(control, File.join(@root, "external-inputs", "receipt.json"))
    assert_layout_error("identity_alias") do
      Layout.preflight(
        @root,
        repository_root: repository_root,
        experiment_name: EXPERIMENT,
        lifecycle: "base",
        external_input_name: "receipt.json",
        input_kind: "receipt"
      )
    end
  end

  def test_diagnostic_creation_is_exclusive
    result = Layout.preflight(
      @root,
      repository_root: repository_root,
      diagnostic_name: "preflight.log"
    )
    assert_equal "diagnostics", result.fetch("diagnostic_role")
    assert_equal 0o400,
                 File.stat(File.join(@root, "diagnostics", "preflight.log")).mode & 0o777
    assert_layout_error("diagnostic_exists") do
      Layout.preflight(
        @root,
        repository_root: repository_root,
        diagnostic_name: "preflight.log"
      )
    end
  end

  def test_diagnostic_entry_count_maximum_and_maximum_plus_one
    diagnostics = File.join(@root, "diagnostics")
    Layout::MAX_DIAGNOSTIC_FILES.times do |index|
      write_private(File.join(diagnostics, "#{index}.log"), "", 0o400)
    end
    Layout.preflight(@root, repository_root: repository_root)
    write_private(File.join(diagnostics, "overflow.log"), "", 0o400)
    assert_layout_error("diagnostic_count") do
      Layout.preflight(@root, repository_root: repository_root)
    end
  end

  def test_diagnostic_file_and_aggregate_maximum_plus_one
    diagnostic = File.join(@root, "diagnostics", "large.log")
    write_private(
      diagnostic,
      "x" * (Layout::MAX_DIAGNOSTIC_FILE_BYTES + 1),
      0o400
    )
    assert_layout_error("file_identity") do
      Layout.preflight(@root, repository_root: repository_root)
    end

    other = fresh_layout("aggregate")
    diagnostics = File.join(other, "diagnostics")
    4.times do |index|
      write_private(
        File.join(diagnostics, "#{index}.log"),
        "x" * Layout::MAX_DIAGNOSTIC_FILE_BYTES,
        0o400
      )
    end
    Layout.preflight(other, repository_root: repository_root)
    write_private(File.join(diagnostics, "overflow.log"), "x", 0o400)
    assert_layout_error("diagnostic_total") do
      Layout.preflight(other, repository_root: repository_root)
    end
  end

  def test_diagnostic_subdirectory_and_special_file_are_rejected
    directory = File.join(@root, "diagnostics", "nested")
    Dir.mkdir(directory, 0o700)
    assert_layout_error do
      Layout.preflight(@root, repository_root: repository_root)
    end

    other = fresh_layout("special-diagnostic")
    fifo_path = File.join(other, "diagnostics", "fifo.log")
    assert system("/usr/bin/mkfifo", fifo_path)
    File.chmod(0o400, fifo_path)
    assert_layout_error do
      Layout.preflight(other, repository_root: repository_root)
    end
  end

  def test_reviewed_diagnostic_wrapper_accepts_the_exact_process_bound
    result = Layout.capture_diagnostic(
      @root,
      name: "exact.log",
      argv: ruby_output_command(Layout::MAX_DIAGNOSTIC_FILE_BYTES),
      repository_root: repository_root
    )
    assert_equal "captured", result.fetch("status")
    path = File.join(@root, "diagnostics", "exact.log")
    assert_equal Layout::MAX_DIAGNOSTIC_FILE_BYTES, File.size(path)
    assert_equal 0o400, File.stat(path).mode & 0o777
  end

  def test_reviewed_diagnostic_wrapper_rejects_maximum_plus_one
    assert_layout_error("diagnostic_process") do
      Layout.capture_diagnostic(
        @root,
        name: "overflow.log",
        argv: ruby_output_command(Layout::MAX_DIAGNOSTIC_FILE_BYTES + 1),
        repository_root: repository_root
      )
    end
    path = File.join(@root, "diagnostics", "overflow.log")
    assert_operator File.size(path), :<=, Layout::MAX_DIAGNOSTIC_FILE_BYTES
    assert_equal 0o400, File.stat(path).mode & 0o777
  end

  def test_reviewed_diagnostic_wrapper_terminates_a_timed_out_process_group
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_layout_error("diagnostic_timeout") do
      Layout.capture_diagnostic(
        @root,
        name: "timeout.log",
        argv: [RbConfig.ruby, "-e", "sleep 30"],
        repository_root: repository_root,
        timeout_seconds: 0.05
      )
    end
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    assert_operator elapsed, :<, 2
  end

  def test_reviewed_diagnostic_wrapper_closes_background_writers
    result = Layout.capture_diagnostic(
      @root,
      name: "background.log",
      argv: [
        RbConfig.ruby,
        "-e",
        "fork { loop { STDOUT.write('x'); STDOUT.flush; sleep 0.01 } }; exit! 0",
      ],
      repository_root: repository_root
    )
    assert_equal "captured", result.fetch("status")
    path = File.join(@root, "diagnostics", "background.log")
    size = File.size(path)
    sleep 0.1
    assert_equal size, File.size(path)
    assert_equal 0o400, File.stat(path).mode & 0o777
  end

  def test_only_an_unpublished_wrapper_file_is_cleaned
    assert_layout_error("diagnostic_failed") do
      Layout.capture_diagnostic(
        @root,
        name: "unpublished.log",
        argv: [File.join(@container, "missing-command")],
        repository_root: repository_root
      )
    end
    refute File.exist?(File.join(@root, "diagnostics", "unpublished.log"))
  end

  def test_errors_and_results_do_not_expose_private_values
    secret_name = "private-receipt-token.json"
    error = assert_layout_error do
      Layout.preflight(
        @root,
        repository_root: repository_root,
        external_input_name: secret_name,
        input_kind: "receipt"
      )
    end
    refute_includes error.message, @root
    refute_includes error.message, secret_name
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

  def create_experiment(root, lifecycle)
    experiment = File.join(root, "experiments", EXPERIMENT)
    Dir.mkdir(experiment, 0o700)
    Layout::BASE_CONTROL_NAMES.each do |name|
      write_private(File.join(experiment, name), "synthetic-#{name}", 0o400)
    end
    Layout::LIFECYCLE_PHASES.fetch(lifecycle).each do |phase|
      directory = File.join(experiment, phase)
      Dir.mkdir(directory, 0o700)
      Layout::PHASE_INVENTORIES.fetch(phase).each do |name|
        write_private(File.join(directory, name), "synthetic-#{name}", 0o400)
      end
    end
    experiment
  end

  def preflight_experiment(lifecycle)
    Layout.preflight(
      @root,
      repository_root: repository_root,
      experiment_name: EXPERIMENT,
      lifecycle: lifecycle
    )
  end

  def preflight_input
    Layout.preflight(
      @root,
      repository_root: repository_root,
      external_input_name: "receipt.json",
      input_kind: "receipt"
    )
  end

  def ruby_output_command(bytes)
    [RbConfig.ruby, "-e", "STDOUT.write('x' * #{bytes})"]
  end

  def assert_layout_error(code = nil)
    error = assert_raises(Error) { yield }
    assert_equal code, error.code if code
    error
  end
end
