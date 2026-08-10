# frozen_string_literal: true

require "fileutils"
require "fiddle/import"
require "pathname"
require "timeout"

module OrchardProbe
  module Lab003Layout
    module Native
      extend Fiddle::Importer
      dlload Fiddle.dlopen(nil)
      extern "int fchdir(int)"
      extern "int mkdirat(int, const char *, unsigned int)"
      extern "int openat(int, const char *, int, unsigned int)"
    end

    ROLE_NAMES = %w[experiments external-inputs diagnostics].freeze
    BASE_CONTROL_NAMES = %w[
      authorized-target-manifest.json
      frozen-oracle.json
      preupload-evidence.json
      installation-acknowledgement.json
      installation-envelope.json
      experiment-directory-binding.json
    ].freeze
    PHASE_INVENTORIES = {
      "enrollment-result" => %w[
        signed-enrollment-receipt.json
        device-selection-confirmation.json
        device-enrollment-binding.json
      ].freeze,
      "run-1-control" => %w[
        run-acknowledgement.json
        collection-challenge.json
        collection-intent.json
      ].freeze,
      "run-1-result" => %w[
        signed-session-export.json
        collection-binding.json
      ].freeze,
      "run-2-control" => %w[
        run-acknowledgement.json
        collection-challenge.json
        collection-intent.json
      ].freeze,
      "run-2-result" => %w[
        signed-session-export.json
        collection-binding.json
      ].freeze,
    }.freeze
    LIFECYCLE_PHASES = {
      "base" => [].freeze,
      "enrollment-closed" => %w[enrollment-result].freeze,
      "run-1-control" => %w[enrollment-result run-1-control].freeze,
      "run-1-closed" => %w[
        enrollment-result
        run-1-control
        run-1-result
      ].freeze,
      "run-2-control" => %w[
        enrollment-result
        run-1-control
        run-1-result
        run-2-control
      ].freeze,
      "complete" => %w[
        enrollment-result
        run-1-control
        run-1-result
        run-2-control
        run-2-result
      ].freeze,
    }.freeze
    INPUT_LIMITS = {
      "receipt" => 16 * 1024,
      "export" => 512 * 1024,
    }.freeze
    MAX_EXTERNAL_INPUT_BYTES = 512 * 1024
    MAX_DIAGNOSTIC_FILES = 16
    MAX_DIAGNOSTIC_FILE_BYTES = 1024 * 1024
    MAX_DIAGNOSTIC_TOTAL_BYTES = 4 * 1024 * 1024
    MAX_DIAGNOSTIC_SECONDS = 30.0
    DIAGNOSTIC_TERMINATION_GRACE_SECONDS = 0.5
    DIAGNOSTIC_POLL_INTERVAL_SECONDS = 0.01
    MAX_ROLE_ENTRIES = 128
    MAX_INVENTORY_PAYLOAD_BYTES = 64 * 1024
    SAFE_NAME = /\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z/.freeze
    EXPERIMENT_NAME = /\A[0-9a-f]{64}\z/.freeze

    class Error < StandardError
      attr_reader :code

      def initialize(code, message)
        @code = code
        super(message)
      end
    end

    BoundObject = Struct.new(:path, :handle, :identity, :kind) do
      def close
        handle.close unless handle.closed?
      end
    end

    class Context
      attr_reader :root, :roles, :experiment, :external_input

      def initialize(root:, roles:, experiment: nil, external_input: nil)
        @root = root
        @roles = roles
        @experiment = experiment
        @external_input = external_input
      end

      def close
        [root, *roles.values, experiment, external_input].compact.reverse_each(&:close)
      end
    end

    module_function

    def prepare(
      root_path,
      repository_root:,
      uid: Process.uid,
      after_role_create: nil,
      after_role_open: nil
    )
      path = new_private_root_path!(root_path, repository_root, uid)
      created = []
      root = nil
      begin
        Dir.mkdir(path, 0o700)
        root = open_directory!(path, uid, exact_mode: 0o700)
        created << created_identity(root)
        ROLE_NAMES.each do |name|
          mkdir_at!(root, name, 0o700)
          expected_identity = created_directory_identity!(root, name, uid)
          created << expected_identity
          after_role_create&.call(name, expected_identity)
          child = open_directory_at!(
            root,
            name,
            uid,
            exact_mode: 0o700,
            expected_identity: expected_identity,
            on_open: after_role_open && lambda do |opened|
              after_role_open.call(name, opened)
            end
          )
          child.close
        end
        root.handle.fsync
        context = open_layout(path, repository_root: repository_root, uid: uid)
        begin
          context.roles.each_value { |role| role.handle.fsync }
          context.root.handle.fsync
        ensure
          context.close
        end
      rescue Error
        cleanup_created_directories!(created, uid)
        raise
      rescue SystemCallError
        cleanup_created_directories!(created, uid)
        fail!("prepare_failed", "LAB-003 private layout could not be created safely")
      ensure
        root&.close
      end
      {
        "status" => "prepared",
        "input_role" => "external-inputs/<bounded-file>",
        "diagnostic_role" => "diagnostics/<exclusive-log>",
      }
    end

    def preflight(
      root_path,
      repository_root:,
      experiment_name: nil,
      lifecycle: nil,
      external_input_name: nil,
      input_kind: nil,
      diagnostic_name: nil,
      uid: Process.uid,
      after_layout_open: nil,
      before_second_check: nil
    )
      context = open_layout(root_path, repository_root: repository_root, uid: uid)
      opened = [context.root, *context.roles.values]
      begin
        acquire_diagnostics_role_lock!(
          context.roles.fetch("diagnostics")
        ) if diagnostic_name
        after_layout_open&.call
        validate_experiments_role!(
          context.roles.fetch("experiments"),
          uid,
          selected_name: experiment_name
        )
        validate_external_inputs_role!(
          context.roles.fetch("external-inputs"),
          uid,
          opened,
          skip_name: external_input_name
        )
        validate_diagnostics_role!(
          context.roles.fetch("diagnostics"),
          uid,
          opened: opened
        )

        if experiment_name || lifecycle
          unless experiment_name && lifecycle
            fail!("experiment_incomplete", "LAB-003 experiment selection is incomplete")
          end
          context.instance_variable_set(
            :@experiment,
            open_experiment!(
              context.roles.fetch("experiments"),
              experiment_name,
              lifecycle,
              uid,
              opened
            )
          )
        end

        if external_input_name || input_kind
          unless external_input_name && input_kind
            fail!("input_incomplete", "LAB-003 external input selection is incomplete")
          end
          context.instance_variable_set(
            :@external_input,
            open_external_input!(
              context.roles.fetch("external-inputs"),
              external_input_name,
              input_kind,
              uid
            )
          )
          opened << context.external_input
        end

        if diagnostic_name
          opened << reserve_diagnostic!(
            context.roles.fetch("diagnostics"),
            diagnostic_name,
            uid
          )
        end

        reject_identity_aliases!(opened)
        before_second_check&.call
        revalidate_opened!(opened, uid)
        validate_experiments_role!(
          context.roles.fetch("experiments"),
          uid,
          selected_name: experiment_name
        )
        validate_external_inputs_role!(context.roles.fetch("external-inputs"), uid)
        validate_diagnostics_role!(context.roles.fetch("diagnostics"), uid)
        if context.experiment
          validate_experiment_inventory_names!(
            context.experiment,
            lifecycle,
            uid
          )
        end
        reject_identity_aliases!(opened)
        {
          "status" => "ready",
          "input_role" => external_input_name ? "external-inputs" : nil,
          "diagnostic_role" => diagnostic_name ? "diagnostics" : nil,
          "experiment_role" => experiment_name ? "experiments/<opaque-id>" : nil,
        }.compact
      ensure
        opened.reverse_each(&:close)
        context.close
      end
    rescue Error
      raise
    rescue SystemCallError
      fail!("preflight_failed", "LAB-003 layout preflight failed closed")
    end

    def capture_diagnostic(
      root_path,
      name:,
      argv:,
      repository_root:,
      uid: Process.uid,
      timeout_seconds: MAX_DIAGNOSTIC_SECONDS
    )
      unless argv.is_a?(Array) && argv.any? && argv.all? { |value| value.is_a?(String) }
        fail!("diagnostic_command", "LAB-003 diagnostic command is invalid")
      end
      timeout_seconds = bounded_diagnostic_timeout!(timeout_seconds)
      context = open_layout(root_path, repository_root: repository_root, uid: uid)
      diagnostic = context.roles.fetch("diagnostics")
      sink = nil
      published = false
      pid = nil
      parent_reaped = false
      process_group_closed = false
      begin
        acquire_diagnostics_role_lock!(diagnostic)
        validate_diagnostics_role!(diagnostic, uid, reserve: true)
        sink = create_direct_file!(diagnostic, name, 0o600, uid)
        diagnostic.identity = identity(diagnostic.handle.stat)
        pid = Process.spawn(
          *argv,
          out: sink.handle,
          err: sink.handle,
          pgroup: true,
          rlimit_fsize: MAX_DIAGNOSTIC_FILE_BYTES
        )
        timed_out = false
        process_status = begin
          Timeout.timeout(timeout_seconds) do
            status = Process.wait2(pid).last
            parent_reaped = true
            status
          end
        rescue Timeout::Error
          timed_out = true
          nil
        ensure
          terminated_status = terminate_process_group!(
            pid,
            parent_reaped: parent_reaped
          )
          process_group_closed = true
          parent_reaped ||= !terminated_status.nil?
        end
        process_status ||= terminated_status
        if timed_out
          fail!("diagnostic_timeout", "LAB-003 diagnostic process exceeded its time bound")
        end
        sink.handle.flush
        sink.handle.fsync
        sink.handle.chmod(0o400)
        sink.identity = identity(sink.handle.stat)
        published = true
        revalidate_opened!([sink], uid, file_mode: 0o400)
        validate_diagnostics_role!(diagnostic, uid)
        unless process_status.success?
          fail!("diagnostic_process", "LAB-003 diagnostic process failed within its bound")
        end
        { "status" => "captured", "diagnostic_role" => "diagnostics" }
      rescue Error
        raise
      rescue SystemCallError
        fail!("diagnostic_failed", "LAB-003 diagnostic capture failed closed")
      ensure
        if pid && !process_group_closed
          terminate_process_group!(pid, parent_reaped: parent_reaped)
        end
        cleanup_unpublished_file!(diagnostic, sink, uid) if sink && !published
        sink&.close
        context.close
      end
    end

    def bounded_diagnostic_timeout!(value)
      seconds = Float(value)
      unless seconds.positive? && seconds.finite? && seconds <= MAX_DIAGNOSTIC_SECONDS
        fail!("diagnostic_timeout_bound", "LAB-003 diagnostic time bound is invalid")
      end
      seconds
    rescue ArgumentError, TypeError
      fail!("diagnostic_timeout_bound", "LAB-003 diagnostic time bound is invalid")
    end

    def terminate_process_group!(pid, parent_reaped:)
      signal_process_group!(pid, "TERM")
      status = parent_reaped ? nil : wait_for_child!(pid)
      unless wait_for_process_group_exit(pid)
        signal_process_group!(pid, "KILL")
        status ||= wait_for_child!(pid) unless parent_reaped
        unless wait_for_process_group_exit(pid)
          fail!("diagnostic_process_group", "LAB-003 diagnostic process group did not close")
        end
      end
      status
    end

    def signal_process_group!(pid, signal)
      Process.kill(signal, -pid)
    rescue Errno::ESRCH
      nil
    end

    def wait_for_child!(pid)
      deadline = monotonic_seconds + DIAGNOSTIC_TERMINATION_GRACE_SECONDS
      loop do
        waited, status = Process.wait2(pid, Process::WNOHANG)
        return status if waited
        return nil if monotonic_seconds >= deadline

        sleep DIAGNOSTIC_POLL_INTERVAL_SECONDS
      end
    rescue Errno::ECHILD
      nil
    end

    def wait_for_process_group_exit(pid)
      deadline = monotonic_seconds + DIAGNOSTIC_TERMINATION_GRACE_SECONDS
      loop do
        return true unless process_group_alive?(pid)
        return false if monotonic_seconds >= deadline

        sleep DIAGNOSTIC_POLL_INTERVAL_SECONDS
      end
    end

    def process_group_alive?(pid)
      Process.kill(0, -pid)
      true
    rescue Errno::ESRCH
      false
    rescue Errno::EPERM
      true
    end

    def monotonic_seconds
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    def open_layout(root_path, repository_root:, uid: Process.uid)
      path = existing_private_root_path!(root_path, repository_root)
      root = open_directory!(path, uid, exact_mode: 0o700)
      roles = {}
      begin
        exact_inventory!(root, ROLE_NAMES, uid)
        ROLE_NAMES.each do |name|
          roles[name] = open_directory_at!(root, name, uid, exact_mode: 0o700)
        end
        reject_identity_aliases!([root, *roles.values])
        Context.new(root: root, roles: roles)
      rescue
        roles.each_value(&:close)
        root.close
        raise
      end
    end

    def open_experiment!(experiments, name, lifecycle, uid, opened)
      unless EXPERIMENT_NAME.match?(name.to_s) && LIFECYCLE_PHASES.key?(lifecycle.to_s)
        fail!("experiment_invalid", "LAB-003 experiment selection is invalid")
      end
      experiment = open_directory_at!(
        experiments,
        name,
        uid,
        exact_mode: 0o700
      )
      opened << experiment
      validate_experiment_inventory!(experiment, lifecycle, uid, opened)
      experiment
    end

    def validate_experiment_inventory_names!(experiment, lifecycle, uid)
      phases = LIFECYCLE_PHASES.fetch(lifecycle.to_s) do
        fail!("lifecycle_invalid", "LAB-003 lifecycle state is invalid")
      end
      exact_inventory!(experiment, BASE_CONTROL_NAMES + phases, uid)
      phases.each do |phase|
        directory = open_directory_at!(
          experiment,
          phase,
          uid,
          exact_mode: 0o700
        )
        begin
          exact_inventory!(directory, PHASE_INVENTORIES.fetch(phase), uid)
        ensure
          directory.close
        end
      end
    rescue SystemCallError
      fail!("phase_inventory", "LAB-003 experiment phase inventory is invalid")
    end

    def validate_experiment_inventory!(experiment, lifecycle, uid, opened)
      phases = LIFECYCLE_PHASES.fetch(lifecycle.to_s) do
        fail!("lifecycle_invalid", "LAB-003 lifecycle state is invalid")
      end
      exact_inventory!(experiment, BASE_CONTROL_NAMES + phases, uid)
      BASE_CONTROL_NAMES.each do |name|
        artifact = open_regular_file_at!(
          experiment,
          name,
          uid,
          maximum_size: MAX_EXTERNAL_INPUT_BYTES,
          exact_mode: 0o400,
          allow_empty: false
        )
        opened << artifact
      end
      phases.each do |phase|
        phase_directory = open_directory_at!(
          experiment,
          phase,
          uid,
          exact_mode: 0o700
        )
        opened << phase_directory
        exact_inventory!(phase_directory, PHASE_INVENTORIES.fetch(phase), uid)
        PHASE_INVENTORIES.fetch(phase).each do |name|
          opened << open_regular_file_at!(
            phase_directory,
            name,
            uid,
            maximum_size: MAX_EXTERNAL_INPUT_BYTES,
            exact_mode: 0o400,
            allow_empty: false
          )
        end
      end
      reject_identity_aliases!(opened)
    end

    def validate_experiments_role!(role, uid, selected_name: nil)
      names = entries(role, uid)
      expected = selected_name ? [selected_name.to_s] : []
      unless names.sort == expected.sort
        fail!(
          "experiment_inventory",
          "LAB-003 experiments role does not match the selected experiment"
        )
      end
      names.each do |name|
        unless EXPERIMENT_NAME.match?(name)
          fail!("experiment_entry", "LAB-003 experiments role has an invalid entry")
        end
        child = open_directory_at!(role, name, uid, exact_mode: 0o700)
        child.close
      end
    end

    def validate_external_inputs_role!(role, uid, opened = nil, skip_name: nil)
      names = entries(role, uid)
      if names.length > 1
        fail!("input_count", "LAB-003 external input role is ambiguous")
      end
      names.each do |name|
        safe_name!(name, "external input")
        next if name == skip_name

        input = open_regular_file_at!(
          role,
          name,
          uid,
          maximum_size: MAX_EXTERNAL_INPUT_BYTES,
          allow_empty: false
        )
        opened ? opened << input : input.close
      end
      reject_identity_aliases!(opened) if opened
    end

    def open_external_input!(role, name, kind, uid)
      safe_name!(name, "external input")
      maximum = INPUT_LIMITS.fetch(kind.to_s) do
        fail!("input_kind", "LAB-003 external input kind is invalid")
      end
      open_regular_file_at!(
        role,
        name,
        uid,
        maximum_size: maximum,
        allow_empty: false
      )
    end

    def validate_diagnostics_role!(role, uid, reserve: false, opened: nil)
      names = entries(role, uid)
      maximum_count = reserve ? MAX_DIAGNOSTIC_FILES - 1 : MAX_DIAGNOSTIC_FILES
      if names.length > maximum_count
        fail!("diagnostic_count", "LAB-003 diagnostics role exceeds its file limit")
      end
      total = 0
      names.each do |name|
        safe_name!(name, "diagnostic")
        diagnostic = open_regular_file_at!(
          role,
          name,
          uid,
          maximum_size: MAX_DIAGNOSTIC_FILE_BYTES,
          exact_mode: 0o400,
          allow_empty: true
        )
        total += diagnostic.identity.fetch(:size)
        opened ? opened << diagnostic : diagnostic.close
        if total > MAX_DIAGNOSTIC_TOTAL_BYTES
          fail!("diagnostic_total", "LAB-003 diagnostics role exceeds its aggregate limit")
        end
      end
      total
    end

    def reserve_diagnostic!(role, name, uid)
      acquire_diagnostics_role_lock!(role)
      validate_diagnostics_role!(role, uid, reserve: true)
      sink = create_direct_file!(role, name, 0o600, uid)
      role.identity = identity(role.handle.stat)
      published = false
      begin
        sink.handle.flush
        sink.handle.fsync
        sink.handle.chmod(0o400)
        revalidate_opened!([sink], uid, file_mode: 0o400)
        sink.identity = identity(sink.handle.stat)
        validate_diagnostics_role!(role, uid)
        published = true
        sink
      ensure
        unless published
          cleanup_unpublished_file!(role, sink, uid)
          sink&.close
        end
      end
    end

    def acquire_diagnostics_role_lock!(role)
      unless role.handle.flock(File::LOCK_EX | File::LOCK_NB)
        fail!(
          "diagnostic_role_lock",
          "LAB-003 diagnostics role is already owned by another controlled lane"
        )
      end
      true
    rescue SystemCallError
      fail!("diagnostic_role_lock", "LAB-003 diagnostics role lock failed closed")
    end

    def new_private_root_path!(raw_path, repository_root, uid)
      absolute_path!(raw_path)
      expanded = File.expand_path(raw_path)
      outside_repository!(expanded, repository_root)
      if File.exist?(expanded) || File.symlink?(expanded)
        fail!("root_exists", "LAB-003 private root must not already exist")
      end
      parent = File.dirname(expanded)
      canonical_parent = canonical_directory_path!(parent, uid, ancestor: true)
      unless File.join(canonical_parent, File.basename(expanded)) == expanded
        fail!("root_component", "LAB-003 private root path contains an alias")
      end
      expanded
    end

    def existing_private_root_path!(raw_path, repository_root)
      absolute_path!(raw_path)
      expanded = File.expand_path(raw_path)
      outside_repository!(expanded, repository_root)
      canonical = canonical_directory_path!(expanded, Process.uid, ancestor: false)
      unless canonical == expanded
        fail!("root_component", "LAB-003 private root path contains an alias")
      end
      canonical
    end

    def absolute_path!(raw_path)
      unless raw_path.is_a?(String) && Pathname.new(raw_path).absolute? &&
             raw_path.valid_encoding? && !raw_path.match?(/[\x00-\x1f\x7f]/)
        fail!("path_invalid", "LAB-003 private root path is invalid")
      end
    end

    def outside_repository!(path, repository_root)
      repository = File.realpath(repository_root)
      if path == repository || path.start_with?("#{repository}#{File::SEPARATOR}")
        fail!("repository_overlap", "LAB-003 private layout must remain outside the repository")
      end
    rescue SystemCallError
      fail!("repository_invalid", "LAB-003 repository boundary could not be verified")
    end

    def canonical_directory_path!(path, uid, ancestor:)
      expanded = File.expand_path(path)
      validate_component_chain!(expanded, uid, ancestor: ancestor)
      File.realpath(expanded)
    rescue SystemCallError
      fail!("directory_invalid", "LAB-003 directory path could not be verified")
    end

    def validate_component_chain!(path, uid, ancestor:)
      current = File::SEPARATOR
      Pathname.new(path).each_filename do |component|
        current = File.join(current, component)
        stat = File.lstat(current)
        unless stat.directory? && !stat.symlink?
          fail!("component_type", "LAB-003 path component is not a real directory")
        end
        next unless ancestor

        writable = (stat.mode & 0o022) != 0
        sticky = (stat.mode & 0o1000) != 0
        if writable && !sticky && stat.uid != uid
          fail!("component_permissions", "LAB-003 path component has unsafe permissions")
        end
      end
    end

    def open_directory!(path, uid, exact_mode:)
      validate_component_chain!(path, uid, ancestor: true)
      flags = File::RDONLY
      flags |= File::NOFOLLOW if defined?(File::NOFOLLOW)
      handle = File.open(path, flags)
      stat = handle.stat
      linked = File.lstat(path)
      unless stat.directory? && !linked.symlink? && stat.uid == uid &&
             (stat.mode & 0o777) == exact_mode && same_identity?(stat, linked)
        handle.close
        fail!("directory_identity", "LAB-003 role directory identity is invalid")
      end
      BoundObject.new(path, handle, identity(stat), :directory)
    rescue Errno::ELOOP
      fail!("directory_symlink", "LAB-003 role directory must not be a symbolic link")
    end

    def open_directory_at!(
      parent,
      name,
      uid,
      exact_mode:,
      expected_identity: nil,
      on_open: nil
    )
      safe_name!(name, "directory")
      flags = File::RDONLY | File::NONBLOCK
      flags |= File::NOFOLLOW if defined?(File::NOFOLLOW)
      handle = open_at!(parent, name, flags, 0, "r")
      path = File.join(parent.path, name)
      opened = handle.stat
      object = BoundObject.new(path, handle, identity(opened), :directory)
      on_open&.call(object)
      stat = handle.stat
      linked = File.lstat(path)
      expected_match = !expected_identity ||
                       (opened.dev == expected_identity.fetch(:device) &&
                        opened.ino == expected_identity.fetch(:inode))
      unless stat.directory? && !linked.symlink? && stat.uid == uid &&
             (stat.mode & 0o777) == exact_mode && same_identity?(opened, stat) &&
             same_identity?(stat, linked) && expected_match
        handle.close
        fail!("directory_identity", "LAB-003 role directory identity is invalid")
      end
      object.identity = identity(stat)
      object
    rescue Errno::ELOOP
      fail!("directory_symlink", "LAB-003 role directory must not be a symbolic link")
    end

    def open_regular_file!(path, uid, maximum_size:, exact_mode: nil, allow_empty:)
      flags = File::RDONLY | File::NONBLOCK
      flags |= File::NOFOLLOW if defined?(File::NOFOLLOW)
      handle = File.open(path, flags)
      stat = handle.stat
      linked = File.lstat(path)
      mode = stat.mode & 0o777
      size_ok = stat.size <= maximum_size && (allow_empty || stat.size.positive?)
      mode_ok = exact_mode ? mode == exact_mode : (mode & 0o077).zero?
      unless stat.file? && !linked.symlink? && stat.uid == uid && mode_ok &&
             size_ok && same_identity?(stat, linked)
        handle.close
        fail!("file_identity", "LAB-003 role file identity or bound is invalid")
      end
      BoundObject.new(path, handle, identity(stat), :file)
    rescue Errno::ELOOP
      fail!("file_symlink", "LAB-003 role file must not be a symbolic link")
    end

    def open_regular_file_at!(
      parent,
      name,
      uid,
      maximum_size:,
      exact_mode: nil,
      allow_empty:
    )
      safe_name!(name, "file")
      flags = File::RDONLY | File::NONBLOCK
      flags |= File::NOFOLLOW if defined?(File::NOFOLLOW)
      handle = open_at!(parent, name, flags, 0, "r")
      path = File.join(parent.path, name)
      stat = handle.stat
      linked = File.lstat(path)
      mode = stat.mode & 0o777
      size_ok = stat.size <= maximum_size && (allow_empty || stat.size.positive?)
      mode_ok = exact_mode ? mode == exact_mode : (mode & 0o077).zero?
      unless stat.file? && !linked.symlink? && stat.uid == uid && mode_ok &&
             size_ok && same_identity?(stat, linked)
        handle.close
        fail!("file_identity", "LAB-003 role file identity or bound is invalid")
      end
      BoundObject.new(path, handle, identity(stat), :file)
    rescue Errno::ELOOP
      fail!("file_symlink", "LAB-003 role file must not be a symbolic link")
    end

    def create_direct_file!(role, name, mode, uid)
      safe_name!(name, "diagnostic")
      path = File.join(role.path, name)
      flags = File::WRONLY | File::CREAT | File::EXCL
      flags |= File::NOFOLLOW if defined?(File::NOFOLLOW)
      handle = open_at!(role, name, flags, mode, "w")
      handle.chmod(mode)
      stat = handle.stat
      linked = File.lstat(path)
      unless stat.file? && stat.uid == uid && (stat.mode & 0o777) == mode &&
             !linked.symlink? && same_identity?(stat, linked)
        handle.close
        fail!("diagnostic_identity", "LAB-003 diagnostic destination is invalid")
      end
      BoundObject.new(path, handle, identity(stat), :file)
    rescue Errno::EEXIST, Errno::ELOOP
      fail!("diagnostic_exists", "LAB-003 diagnostic destination already exists")
    end

    def cleanup_unpublished_file!(role, object, uid)
      return unless object

      current = File.lstat(object.path)
      held = object.handle.stat
      return unless current.file? && current.uid == uid && same_identity?(current, held)

      File.unlink(object.path)
      role.handle.fsync
    rescue SystemCallError
      nil
    end

    def cleanup_created_directories!(created, uid)
      created.reverse_each do |record|
        path = record.fetch(:path)
        stat = File.lstat(path)
        next unless stat.directory? && !stat.symlink? && stat.uid == uid &&
                    stat.dev == record.fetch(:device) &&
                    stat.ino == record.fetch(:inode)

        Dir.rmdir(path)
      rescue SystemCallError
        nil
      end
    end

    def created_identity(object)
      {
        path: object.path,
        device: object.identity.fetch(:device),
        inode: object.identity.fetch(:inode),
      }
    end

    def created_directory_identity!(parent, name, uid)
      path = File.join(parent.path, name)
      stat = File.lstat(path)
      unless stat.directory? && !stat.symlink? && stat.uid == uid
        fail!("directory_identity", "LAB-003 newly created role identity is invalid")
      end
      {
        path: path,
        device: stat.dev,
        inode: stat.ino,
      }
    end

    def exact_inventory!(directory, expected, uid)
      observed = entries(directory, uid)
      unless observed.sort == expected.sort
        fail!("inventory", "LAB-003 role inventory does not match its lifecycle state")
      end
    end

    def entries(directory, uid)
      revalidate_opened!([directory], uid)
      names = descriptor_entries!(directory)
      if names.any? { |name| !name.valid_encoding? || name.match?(/[\x00-\x1f\x7f]/) }
        fail!("entry_name", "LAB-003 role contains an invalid entry name")
      end
      revalidate_opened!([directory], uid)
      names
    rescue SystemCallError
      fail!("inventory_read", "LAB-003 role inventory could not be read safely")
    end

    def descriptor_entries!(directory)
      reader, writer = IO.pipe
      pid = fork do
        reader.close
        exit! 126 if Native.fchdir(directory.handle.fileno).nonzero?

        names = []
        Dir.foreach(".") do |name|
          next if %w[. ..].include?(name)

          names << name
          exit! 125 if names.length > MAX_ROLE_ENTRIES
        end
        Marshal.dump(names, writer)
        writer.close
        exit! 0
      rescue StandardError
        exit! 126
      end
      writer.close
      payload = read_bounded_pipe(reader, MAX_INVENTORY_PAYLOAD_BYTES)
      reader.close
      _, status = Process.wait2(pid)
      unless status.success? && payload.bytesize <= MAX_INVENTORY_PAYLOAD_BYTES
        fail!("inventory_bound", "LAB-003 role inventory exceeds its bound")
      end
      names = Marshal.load(payload)
      unless names.is_a?(Array) && names.length <= MAX_ROLE_ENTRIES &&
             names.all? { |name| name.is_a?(String) }
        fail!("inventory_invalid", "LAB-003 role inventory is invalid")
      end
      names
    rescue TypeError, ArgumentError
      fail!("inventory_invalid", "LAB-003 role inventory is invalid")
    ensure
      reader&.close unless reader&.closed?
      writer&.close unless writer&.closed?
    end

    def read_bounded_pipe(reader, maximum)
      payload = +""
      loop do
        chunk = reader.readpartial(8192)
        remaining = maximum + 1 - payload.bytesize
        payload << chunk.byteslice(0, remaining) if remaining.positive?
      end
    rescue EOFError
      payload
    end

    def open_at!(parent, name, flags, mode, io_mode)
      descriptor = Native.openat(parent.handle.fileno, name, flags, mode)
      if descriptor.negative?
        raise SystemCallError.new("openat", Fiddle.last_error)
      end
      handle = File.for_fd(descriptor, io_mode)
      handle.close_on_exec = true
      handle
    rescue
      IO.for_fd(descriptor).close if descriptor && descriptor >= 0
      raise
    end

    def mkdir_at!(parent, name, mode)
      safe_name!(name, "directory")
      result = Native.mkdirat(parent.handle.fileno, name, mode)
      return if result.zero?

      raise SystemCallError.new("mkdirat", Fiddle.last_error)
    end

    def safe_name!(name, label)
      unless name.is_a?(String) && SAFE_NAME.match?(name) &&
             !%w[. ..].include?(name)
        fail!("name_invalid", "LAB-003 #{label} name is invalid")
      end
    end

    def reject_identity_aliases!(objects)
      identities = objects.compact.map do |object|
        [object.identity.fetch(:device), object.identity.fetch(:inode)]
      end
      unless identities.uniq.length == identities.length
        fail!("identity_alias", "LAB-003 role objects must not alias one another")
      end
    end

    def revalidate_opened!(objects, uid, file_mode: nil)
      objects.compact.each do |object|
        held = object.handle.stat
        linked = File.lstat(object.path)
        expected = object.identity
        valid = same_identity?(held, linked) &&
                held.dev == expected.fetch(:device) &&
                held.ino == expected.fetch(:inode) &&
                held.uid == uid && held.size == expected.fetch(:size) &&
                held.mtime.to_f == expected.fetch(:mtime)
        if object.kind == :directory
          valid &&= held.directory? && !linked.symlink? &&
                    (held.mode & 0o777) == expected.fetch(:mode)
        else
          mode = file_mode || expected.fetch(:mode)
          valid &&= held.file? && !linked.symlink? && (held.mode & 0o777) == mode
        end
        unless valid
          fail!("identity_changed", "LAB-003 role object changed during validation")
        end
      end
    rescue SystemCallError
      fail!("identity_changed", "LAB-003 role object changed during validation")
    end

    def identity(stat)
      {
        device: stat.dev,
        inode: stat.ino,
        uid: stat.uid,
        mode: stat.mode & 0o777,
        size: stat.size,
        mtime: stat.mtime.to_f,
      }
    end

    def same_identity?(left, right)
      left.dev == right.dev && left.ino == right.ino
    end

    def fail!(code, message)
      raise Error.new(code, message)
    end
  end
end
