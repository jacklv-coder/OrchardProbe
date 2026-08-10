# frozen_string_literal: true

require "digest"

require_relative "lab003_layout"

module OrchardProbe
  module Lab004OperatorBoundary
    Layout = OrchardProbe::Lab003Layout

    Profile = Struct.new(
      :before_lifecycle,
      :after_lifecycle,
      :input_kind,
      keyword_init: true
    )

    PROFILES = {
      "operator-start-enrollment" => Profile.new(
        before_lifecycle: nil,
        after_lifecycle: "base",
        input_kind: nil
      ),
      "operator-close-enrollment" => Profile.new(
        before_lifecycle: "base",
        after_lifecycle: "enrollment-closed",
        input_kind: "receipt"
      ),
      "operator-start-run-1" => Profile.new(
        before_lifecycle: "enrollment-closed",
        after_lifecycle: "run-1-control",
        input_kind: nil
      ),
      "operator-close-run-1" => Profile.new(
        before_lifecycle: "run-1-control",
        after_lifecycle: "run-1-closed",
        input_kind: "export"
      ),
      "operator-start-run-2" => Profile.new(
        before_lifecycle: "run-1-closed",
        after_lifecycle: "run-2-control",
        input_kind: nil
      ),
      "operator-close-run-2" => Profile.new(
        before_lifecycle: "run-2-control",
        after_lifecycle: "complete",
        input_kind: "export"
      ),
      "operator-verify" => Profile.new(
        before_lifecycle: "complete",
        after_lifecycle: "complete",
        input_kind: nil
      ),
    }.freeze
    HELPER_OPERATIONS = {
      "operator-start-enrollment" => "operator-start-enrollment",
      "operator-close-enrollment" => "operator-close-enrollment",
      "operator-start-run-1" => "operator-start-run",
      "operator-close-run-1" => "operator-close-run",
      "operator-start-run-2" => "operator-start-run",
      "operator-close-run-2" => "operator-close-run",
      "operator-verify" => "operator-verify",
    }.freeze
    DIAGNOSTIC_MESSAGES = {
      "helper-success" => "LAB-004 Host helper completed within the reviewed boundary.\n",
      "helper-failure" => "LAB-004 Host helper failed within the reviewed boundary.\n",
    }.freeze
    MAX_DIAGNOSTIC_MESSAGE_BYTES = DIAGNOSTIC_MESSAGES.values.map(&:bytesize).max

    class Error < StandardError
      attr_reader :code

      def initialize(code, message)
        @code = code
        super(message)
      end
    end

    class Boundary
      attr_reader :operation, :profile, :context, :experiment_name,
                  :diagnostic_name, :opened, :external_input_digest,
                  :initial_diagnostic_names, :diagnostic, :diagnostic_digest,
                  :diagnostic_status,
                  :transition_experiment_name

      def initialize(
        operation:,
        profile:,
        context:,
        experiment_name:,
        diagnostic_name:,
        opened:,
        external_input_digest:,
        initial_diagnostic_names:,
        initial_diagnostic_digests:,
        protocol_digests:
      )
        @operation = operation
        @profile = profile
        @context = context
        @experiment_name = experiment_name
        @diagnostic_name = diagnostic_name
        @opened = opened
        @external_input_digest = external_input_digest
        @initial_diagnostic_names = initial_diagnostic_names.freeze
        @initial_diagnostic_digests = initial_diagnostic_digests.dup.freeze
        @protocol_digests = protocol_digests.dup.freeze
        @diagnostic = nil
        @diagnostic_digest = nil
        @diagnostic_status = nil
        @diagnostic_published = false
        @transition_experiment_name = nil
        @helper_authorized = false
        @active = true
      end

      def active?
        @active
      end

      def deactivate!
        @active = false
      end

      def primary_directory
        context.experiment || context.roles.fetch("experiments")
      end

      def external_input
        context.external_input
      end

      def record_diagnostic!(object, digest, status)
        @diagnostic = object
        @diagnostic_digest = digest
        @diagnostic_status = status
      end

      def mark_diagnostic_published!
        @diagnostic_published = true
      end

      def diagnostic_published?
        @diagnostic_published
      end

      def transition_captured?
        !@transition_experiment_name.nil?
      end

      def helper_authorized?
        @helper_authorized
      end

      def record_helper_authorization!
        @helper_authorized = true
      end

      def protocol_digest(relative)
        @protocol_digests[relative]
      end

      def initial_diagnostic_digest(name)
        @initial_diagnostic_digests[name]
      end

      def record_transition!(experiment_name, objects, digests)
        if (digests.keys & @protocol_digests.keys).any?
          raise Error.new("protocol_identity", "LAB-004 protocol identity set is invalid")
        end
        @transition_experiment_name = experiment_name
        @opened.concat(objects)
        @protocol_digests = @protocol_digests.merge(digests).freeze
      end

      def sanitized_result(status)
        {
          "status" => status,
          "operation" => operation,
          "experiment_role" => experiment_name ? "experiments/<opaque-id>" : "experiments",
          "input_role" => profile.input_kind ? "external-inputs" : nil,
          "diagnostic_role" => "diagnostics",
        }.compact
      end
    end

    module_function

    def preflight(
      root_path,
      operation:,
      experiment_name: nil,
      external_input_name: nil,
      diagnostic_name:,
      repository_root:,
      uid: Process.uid
    )
      boundary = open_boundary!(
        root_path,
        operation: operation,
        experiment_name: experiment_name,
        external_input_name: external_input_name,
        diagnostic_name: diagnostic_name,
        repository_root: repository_root,
        uid: uid
      )
      boundary.sanitized_result("ready")
    ensure
      close_boundary!(boundary)
    end

    def with_operation(
      root_path,
      operation:,
      experiment_name: nil,
      external_input_name: nil,
      diagnostic_name:,
      repository_root:,
      uid: Process.uid
    )
      unless block_given?
        fail!("callback_missing", "LAB-004 device-free operation callback is missing")
      end

      boundary = open_boundary!(
        root_path,
        operation: operation,
        experiment_name: experiment_name,
        external_input_name: external_input_name,
        diagnostic_name: diagnostic_name,
        repository_root: repository_root,
        uid: uid
      )
      result = nil
      callback_error = nil
      closure_error = nil
      cleanup_error = nil
      begin
        result = yield(boundary)
      rescue StandardError => error
        callback_error = error
      ensure
        begin
          if callback_error
            cleanup_boundary_diagnostic!(boundary, uid)
            validate_closure!(
              boundary,
              result: nil,
              repository_root: repository_root,
              uid: uid,
              completed: false
            )
          else
            validate_closure!(
              boundary,
              result: result,
              repository_root: repository_root,
              uid: uid,
              completed: true
            )
          end
        rescue StandardError => error
          closure_error = error
          begin
            cleanup_boundary_diagnostic!(boundary, uid)
          rescue StandardError => error
            cleanup_error = error
          end
        ensure
          close_boundary!(boundary)
        end
      end

      if cleanup_error
        fail!(
          "diagnostic_cleanup_indeterminate",
          "LAB-004 diagnostic cleanup is indeterminate after closure failure"
        )
      end
      if closure_error
        fail!("closure_failed", "LAB-004 role closure failed closed")
      end
      if callback_error
        fail!("operation_failed", "LAB-004 Host operation failed within its boundary")
      end

      boundary.sanitized_result("closed")
    end

    def read_external_input(boundary)
      active_boundary!(boundary)
      input = boundary.external_input
      unless input
        fail!("input_unavailable", "LAB-004 operation has no external input")
      end
      maximum = Layout::INPUT_LIMITS.fetch(boundary.profile.input_kind)
      content = read_bounded_input!(input, maximum)
      unless Digest::SHA256.digest(content) == boundary.external_input_digest
        fail!("input_changed", "LAB-004 external input changed during operation")
      end
      content
    rescue SystemCallError
      fail!("input_read", "LAB-004 external input could not be read safely")
    end

    def authorize_helper_bindings!(boundary, operation:, bindings:, input:)
      active_boundary!(boundary)
      if boundary.helper_authorized? || boundary.transition_captured? || boundary.diagnostic
        fail!("helper_state", "LAB-004 Host helper authorization is out of order")
      end
      revalidate_prestate!(boundary)
      unless HELPER_OPERATIONS.fetch(boundary.operation) == operation &&
             bindings.is_a?(Array) && bindings.length == 1
        fail!("helper_scope", "LAB-004 Host helper scope is invalid")
      end
      primary = bindings.first
      unless primary.is_a?(Hash) &&
             primary[:handle].respond_to?(:stat) &&
             primary[:identity].is_a?(Array)
        fail!("helper_binding", "LAB-004 Host helper binding is invalid")
      end
      expected = boundary.primary_directory
      held = primary.fetch(:handle).stat
      expected_stat = expected.handle.stat
      identity = primary.fetch(:identity)
      unless held.dev == expected_stat.dev && held.ino == expected_stat.ino &&
             identity[0] == held.dev && identity[1] == held.ino
        fail!("helper_binding", "LAB-004 Host helper binding is outside its role")
      end
      authorize_helper_input!(boundary, operation, input)
      boundary.record_helper_authorization!
      true
    rescue KeyError, SystemCallError
      fail!("helper_binding", "LAB-004 Host helper binding is invalid")
    end

    def capture_transition!(boundary, result:)
      active_boundary!(boundary)
      unless boundary.helper_authorized?
        fail!("helper_authorization", "LAB-004 Host helper was not authorized")
      end
      uid = boundary.context.root.identity.fetch(:uid)
      if boundary.transition_captured? || boundary.diagnostic
        fail!("transition_state", "LAB-004 Host transition capture is out of order")
      end
      experiment_name = closure_experiment_name!(boundary, result, true)
      experiments = boundary.context.roles.fetch("experiments")
      current = []
      retained = []
      begin
        refresh_mutated_directory!(experiments, uid)
        Layout.validate_experiments_role!(
          experiments,
          uid,
          selected_name: experiment_name
        )
        Layout.open_experiment!(
          experiments,
          experiment_name,
          boundary.profile.after_lifecycle,
          uid,
          current
        )
        before = protocol_descendants(boundary.opened, experiments)
        after = protocol_descendants(current, experiments)
        compare_protocol_subset!(before, after, uid, boundary)
        validate_external_role_exact!(boundary, uid)
        validate_diagnostics_role_exact!(boundary, uid)
        Layout.reject_identity_aliases!(
          [boundary.context.root, *boundary.context.roles.values, *current,
           boundary.context.external_input].compact
        )
        Layout.revalidate_opened!(boundary.opened, uid)
        Layout.revalidate_opened!(current, uid)
        added = after.keys - before.keys
        candidates = added.map { |name| after.fetch(name) }
        digests = capture_protocol_digests!(after.slice(*added))
        boundary.record_transition!(experiment_name, candidates, digests)
        retained = candidates
        true
      rescue Layout::Error => error
        fail!(error.code, error.message.sub("LAB-003", "LAB-004"))
      ensure
        current.each { |object| object.close unless retained.include?(object) }
      end
    end

    def publish_diagnostic(boundary, status)
      active_boundary!(boundary)
      if status.to_s == "helper-success"
        unless boundary.helper_authorized?
          fail!("helper_authorization", "LAB-004 Host helper was not authorized")
        end
        unless boundary.transition_captured?
          fail!("transition_missing", "LAB-004 Host transition was not captured")
        end
      end
      status_name = status.to_s.dup.freeze
      message = DIAGNOSTIC_MESSAGES.fetch(status_name) do
        fail!("diagnostic_status", "LAB-004 diagnostic status is invalid")
      end
      role = boundary.context.roles.fetch("diagnostics")
      uid = boundary.context.root.identity.fetch(:uid)
      sink = nil
      tracked = false
      published = false
      begin
        if boundary.diagnostic
          fail!("diagnostic_exists", "LAB-004 diagnostic result already exists")
        end
        validate_diagnostics_capacity!(role, uid)
        sink = Layout.create_direct_file!(role, boundary.diagnostic_name, 0o600, uid)
        boundary.record_diagnostic!(sink, Digest::SHA256.digest(message), status_name)
        boundary.opened << sink
        tracked = true
        role.identity = Layout.identity(role.handle.stat)
        sink.handle.write(message)
        sink.handle.flush
        sink.handle.fsync
        sink.handle.chmod(0o400)
        sink.identity = Layout.identity(sink.handle.stat)
        Layout.revalidate_opened!([sink], uid, file_mode: 0o400)
        # create_direct_file! deliberately returns a write-only descriptor.
        # LOCK_EX is valid for that descriptor on Linux and preserves the
        # single-writer diagnostic publication contract through closure.
        unless sink.handle.flock(File::LOCK_EX | File::LOCK_NB)
          fail!("diagnostic_lock", "LAB-004 diagnostic result lock could not be acquired")
        end
        Layout.validate_diagnostics_role!(role, uid)
        boundary.mark_diagnostic_published!
        published = true
        { "status" => "recorded", "diagnostic_role" => "diagnostics" }
      rescue Layout::Error => error
        fail!(error.code, error.message.sub("LAB-003", "LAB-004"))
      rescue SystemCallError
        fail!("diagnostic_failed", "LAB-004 diagnostic record failed closed")
      ensure
        unless published || tracked
          Layout.cleanup_unpublished_file!(role, sink, uid) if sink
          role.identity = Layout.identity(role.handle.stat) if sink
          sink&.close
        end
      end
    end

    def authorize_helper_input!(boundary, operation, input)
      unless input.is_a?(String)
        fail!("helper_input", "LAB-004 Host helper input is invalid")
      end
      case operation
      when "operator-close-enrollment"
        expected = read_external_input(boundary)
        prefix, separator, receipt = input.partition("\n")
        unless separator == "\n" && /\A[0-9a-f]{64}\z/.match?(prefix) &&
               receipt == expected
          fail!("helper_input", "LAB-004 enrollment input is outside its role")
        end
      when "operator-close-run"
        unless input == read_external_input(boundary)
          fail!("helper_input", "LAB-004 run input is outside its role")
        end
      end
      true
    end

    def open_boundary!(
      root_path,
      operation:,
      experiment_name:,
      external_input_name:,
      diagnostic_name:,
      repository_root:,
      uid:
    )
      profile = PROFILES.fetch(operation.to_s) do
        fail!("operation_invalid", "LAB-004 Host operation is invalid")
      end
      validate_selection!(
        profile,
        experiment_name,
        external_input_name,
        diagnostic_name
      )

      context = Layout.open_layout(
        root_path,
        repository_root: repository_root,
        uid: uid
      )
      opened = [context.root, *context.roles.values]
      boundary = nil
      begin
        Layout.validate_experiments_role!(
          context.roles.fetch("experiments"),
          uid,
          selected_name: experiment_name
        )
        Layout.validate_external_inputs_role!(
          context.roles.fetch("external-inputs"),
          uid,
          opened,
          skip_name: external_input_name
        )
        diagnostics_role = context.roles.fetch("diagnostics")
        validate_diagnostics_capacity!(
          diagnostics_role,
          uid,
          opened: opened
        )
        initial_diagnostic_names = Layout.entries(diagnostics_role, uid)
        reject_existing_diagnostic!(
          context.roles.fetch("diagnostics"),
          diagnostic_name,
          uid
        )

        if profile.before_lifecycle
          context.instance_variable_set(
            :@experiment,
            Layout.open_experiment!(
              context.roles.fetch("experiments"),
              experiment_name,
              profile.before_lifecycle,
              uid,
              opened
            )
          )
        end
        if profile.input_kind
          context.instance_variable_set(
            :@external_input,
            Layout.open_external_input!(
              context.roles.fetch("external-inputs"),
              external_input_name,
              profile.input_kind,
              uid
            )
          )
          opened << context.external_input
        end

        Layout.reject_identity_aliases!(opened)
        Layout.revalidate_opened!(opened, uid)
        external_input_digest = if context.external_input
                                  Digest::SHA256.digest(
                                    read_bounded_input!(
                                      context.external_input,
                                      Layout::INPUT_LIMITS.fetch(profile.input_kind)
                                    )
                                  )
                                end
        initial_diagnostic_digests = capture_initial_diagnostic_digests!(
          diagnostic_descendants(opened, diagnostics_role)
        )
        protocol_digests = capture_protocol_digests!(
          protocol_descendants(opened, context.roles.fetch("experiments"))
        )
        boundary = Boundary.new(
          operation: operation.to_s,
          profile: profile,
          context: context,
          experiment_name: experiment_name,
          diagnostic_name: diagnostic_name,
          opened: opened,
          external_input_digest: external_input_digest,
          initial_diagnostic_names: initial_diagnostic_names,
          initial_diagnostic_digests: initial_diagnostic_digests,
          protocol_digests: protocol_digests
        )
        revalidate_prestate!(boundary, uid)
      rescue
        opened.reverse_each(&:close)
        context.close
        raise
      end
      boundary
    rescue Layout::Error => error
      fail!(error.code, error.message.sub("LAB-003", "LAB-004"))
    rescue SystemCallError
      fail!("boundary_open", "LAB-004 private role boundary could not be opened safely")
    end

    def validate_selection!(
      profile,
      experiment_name,
      external_input_name,
      diagnostic_name
    )
      Layout.safe_name!(diagnostic_name, "diagnostic")
      if profile.before_lifecycle
        unless Layout::EXPERIMENT_NAME.match?(experiment_name.to_s)
          fail!("experiment_required", "LAB-004 operation requires one experiment")
        end
      elsif experiment_name
        fail!("experiment_forbidden", "LAB-004 enrollment start requires an empty role")
      end
      if profile.input_kind
        Layout.safe_name!(external_input_name, "external input")
      elsif external_input_name
        fail!("input_forbidden", "LAB-004 operation does not accept external input")
      end
    rescue Layout::Error => error
      fail!(error.code, error.message.sub("LAB-003", "LAB-004"))
    end

    def reject_existing_diagnostic!(role, name, uid)
      if Layout.entries(role, uid).include?(name)
        fail!("diagnostic_exists", "LAB-004 diagnostic destination already exists")
      end
    end

    def validate_closure!(boundary, result:, repository_root:, uid:, completed:)
      active_boundary!(boundary)
      if completed && !boundary.transition_captured?
        fail!("transition_missing", "LAB-004 Host transition was not captured")
      end
      experiment_name = closure_experiment_name!(boundary, result, completed)
      lifecycle = completed ? boundary.profile.after_lifecycle : boundary.profile.before_lifecycle
      context = Layout.open_layout(
        boundary.context.root.path,
        repository_root: repository_root,
        uid: uid
      )
      opened = [context.root, *context.roles.values]
      begin
        compare_stable_directory!(boundary.context.root, context.root)
        Layout::ROLE_NAMES.each do |name|
          compare_stable_directory!(
            boundary.context.roles.fetch(name),
            context.roles.fetch(name)
          )
        end
        Layout.validate_experiments_role!(
          context.roles.fetch("experiments"),
          uid,
          selected_name: experiment_name
        )
        if lifecycle
          context.instance_variable_set(
            :@experiment,
            Layout.open_experiment!(
              context.roles.fetch("experiments"),
              experiment_name,
              lifecycle,
              uid,
              opened
            )
          )
          if boundary.context.experiment
            compare_stable_directory!(boundary.context.experiment, context.experiment)
          end
          compare_protocol_subset!(
            protocol_descendants(
              boundary.opened,
              boundary.context.roles.fetch("experiments")
            ),
            protocol_descendants(
              opened,
              context.roles.fetch("experiments")
            ),
            uid,
            boundary
          )
        end
        Layout.validate_external_inputs_role!(
          context.roles.fetch("external-inputs"),
          uid,
          opened,
          skip_name: boundary.profile.input_kind && boundary.context.external_input.path.split(File::SEPARATOR).last
        )
        expected_external_names = if boundary.profile.input_kind
                                    [File.basename(boundary.context.external_input.path)]
                                  else
                                    []
                                  end
        unless Layout.entries(
          context.roles.fetch("external-inputs"),
          uid
        ).sort == expected_external_names.sort
          fail!("input_inventory", "LAB-004 external input inventory changed")
        end
        if boundary.profile.input_kind
          name = File.basename(boundary.context.external_input.path)
          context.instance_variable_set(
            :@external_input,
            Layout.open_external_input!(
              context.roles.fetch("external-inputs"),
              name,
              boundary.profile.input_kind,
              uid
            )
          )
          opened << context.external_input
          compare_stable_file!(
            boundary.context.external_input,
            context.external_input,
            boundary.external_input_digest,
            Layout::INPUT_LIMITS.fetch(boundary.profile.input_kind)
          )
        end
        validate_diagnostic_closure!(boundary, context, opened, uid, completed)
        Layout.reject_identity_aliases!(opened)
        Layout.revalidate_opened!(opened, uid)
      ensure
        opened.reverse_each(&:close)
        context.close
      end
      true
    rescue Layout::Error => error
      fail!(error.code, error.message.sub("LAB-003", "LAB-004"))
    end

    def closure_experiment_name!(boundary, result, completed)
      return boundary.experiment_name unless completed
      unless result.is_a?(Hash) &&
             Layout::EXPERIMENT_NAME.match?(result["experiment_id"].to_s)
        fail!("result_invalid", "LAB-004 Host result is invalid")
      end
      result_name = result.fetch("experiment_id")
      if boundary.experiment_name && result_name != boundary.experiment_name
        fail!("result_experiment", "LAB-004 Host result changed experiment scope")
      end
      result_name
    end

    def compare_stable_directory!(before, after)
      left = before.handle.stat
      right = after.handle.stat
      unless left.directory? && right.directory? &&
             left.dev == right.dev && left.ino == right.ino &&
             left.uid == right.uid &&
             (left.mode & 0o777) == (right.mode & 0o777)
        fail!("directory_changed", "LAB-004 role directory changed during operation")
      end
    rescue SystemCallError
      fail!("directory_changed", "LAB-004 role directory changed during operation")
    end

    def revalidate_prestate!(boundary, uid = boundary.context.root.identity.fetch(:uid))
      active_boundary!(boundary)
      experiments = boundary.context.roles.fetch("experiments")
      refresh_mutated_directory!(experiments, uid)
      Layout.validate_experiments_role!(
        experiments,
        uid,
        selected_name: boundary.experiment_name
      )
      current = []
      begin
        if boundary.profile.before_lifecycle
          Layout.open_experiment!(
            experiments,
            boundary.experiment_name,
            boundary.profile.before_lifecycle,
            uid,
            current
          )
          compare_protocol_subset!(
            protocol_descendants(boundary.opened, experiments),
            protocol_descendants(current, experiments),
            uid,
            boundary
          )
        end
        validate_external_role_exact!(boundary, uid)
        validate_diagnostics_role_exact!(boundary, uid)
        Layout.revalidate_opened!(boundary.opened, uid)
        true
      ensure
        current.reverse_each(&:close)
      end
    rescue Layout::Error => error
      fail!(error.code, error.message.sub("LAB-003", "LAB-004"))
    end

    def validate_external_role_exact!(boundary, uid)
      role = boundary.context.roles.fetch("external-inputs")
      refresh_mutated_directory!(role, uid)
      expected = boundary.profile.input_kind ? [File.basename(boundary.context.external_input.path)] : []
      unless Layout.entries(role, uid).sort == expected.sort
        fail!("input_inventory", "LAB-004 external input inventory changed")
      end
      Layout.validate_external_inputs_role!(
        role,
        uid,
        nil,
        skip_name: expected.first
      )
      return true unless boundary.profile.input_kind

      content = read_external_input(boundary)
      unless Digest::SHA256.digest(content) == boundary.external_input_digest
        fail!("input_changed", "LAB-004 external input changed during operation")
      end
      true
    end

    def validate_diagnostics_role_exact!(boundary, uid)
      role = boundary.context.roles.fetch("diagnostics")
      refresh_mutated_directory!(role, uid)
      unless Layout.entries(role, uid).sort == boundary.initial_diagnostic_names.sort
        fail!("diagnostic_inventory", "LAB-004 diagnostic inventory changed")
      end
      current = []
      begin
        validate_diagnostics_capacity!(
          role,
          uid,
          opened: current
        )
        compare_initial_diagnostics!(boundary, current, role)
      ensure
        current.reverse_each(&:close)
      end
      true
    end

    def validate_diagnostics_capacity!(role, uid, opened: nil)
      total = Layout.validate_diagnostics_role!(
        role,
        uid,
        reserve: true,
        opened: opened
      )
      if total > Layout::MAX_DIAGNOSTIC_TOTAL_BYTES - MAX_DIAGNOSTIC_MESSAGE_BYTES
        fail!("diagnostic_total", "LAB-004 diagnostics role lacks result capacity")
      end
      total
    end

    def protocol_descendants(objects, experiments_role)
      prefix = "#{experiments_role.path}#{File::SEPARATOR}"
      objects.each_with_object({}) do |object, result|
        next unless object.path.start_with?(prefix)

        relative = object.path.delete_prefix(prefix)
        if relative.empty? || result.key?(relative)
          fail!("protocol_identity", "LAB-004 protocol identity set is invalid")
        end
        result[relative] = object
      end
    end

    def diagnostic_descendants(objects, diagnostics_role)
      prefix = "#{diagnostics_role.path}#{File::SEPARATOR}"
      objects.each_with_object({}) do |object, result|
        next unless object.kind == :file && object.path.start_with?(prefix)

        relative = object.path.delete_prefix(prefix)
        if relative.empty? || relative.include?(File::SEPARATOR) || result.key?(relative)
          fail!("diagnostic_identity", "LAB-004 diagnostic identity set is invalid")
        end
        result[relative] = object
      end
    end

    def capture_initial_diagnostic_digests!(descendants)
      descendants.each_with_object({}) do |(name, object), result|
        unless object.handle.flock(File::LOCK_SH | File::LOCK_NB)
          fail!("diagnostic_lock", "LAB-004 retained diagnostic is already in use")
        end
        content = read_bounded_file!(object, Layout::MAX_DIAGNOSTIC_FILE_BYTES, false)
        result[name] = Digest::SHA256.digest(content)
      end
    rescue SystemCallError
      fail!("diagnostic_lock", "LAB-004 retained diagnostic lock could not be acquired")
    end

    def compare_initial_diagnostics!(boundary, current_objects, current_role)
      before = diagnostic_descendants(
        boundary.opened,
        boundary.context.roles.fetch("diagnostics")
      )
      after = diagnostic_descendants(current_objects, current_role)
      boundary.initial_diagnostic_names.each do |name|
        prior = before[name]
        current = after[name]
        digest = boundary.initial_diagnostic_digest(name)
        unless prior && current && digest
          fail!("diagnostic_identity", "LAB-004 retained diagnostic identity changed")
        end
        compare_stable_diagnostic!(prior, current, digest)
      end
      true
    end

    def compare_protocol_subset!(before, after, uid, boundary)
      before.each do |relative, prior|
        current = after[relative]
        unless current && prior.kind == current.kind
          fail!("protocol_identity", "LAB-004 protocol descendants changed")
        end
        left = prior.handle.stat
        right = current.handle.stat
        unless left.dev == right.dev && left.ino == right.ino &&
               left.uid == uid && right.uid == uid
          fail!("protocol_identity", "LAB-004 protocol descendants changed")
        end
        if prior.kind == :directory
          unless left.directory? && right.directory? &&
                 (left.mode & 0o777) == prior.identity.fetch(:mode) &&
                 (right.mode & 0o777) == current.identity.fetch(:mode)
            fail!("protocol_identity", "LAB-004 protocol descendants changed")
          end
          prior.identity = Layout.identity(left)
          Layout.revalidate_opened!([prior, current], uid)
        else
          Layout.revalidate_opened!([prior, current], uid)
          expected_digest = boundary.protocol_digest(relative)
          unless expected_digest &&
                 protocol_file_digest!(prior) == expected_digest
            fail!("protocol_content", "LAB-004 protocol artifact content changed")
          end
        end
      end
      true
    rescue SystemCallError
      fail!("protocol_identity", "LAB-004 protocol descendants changed")
    end

    def capture_protocol_digests!(descendants)
      descendants.each_with_object({}) do |(relative, object), result|
        next if object.kind == :directory

        unless object.handle.flock(File::LOCK_SH | File::LOCK_NB)
          fail!("protocol_lock", "LAB-004 protocol artifact is already in use")
        end
        result[relative] = protocol_file_digest!(object)
      end
    rescue SystemCallError
      fail!("protocol_lock", "LAB-004 protocol artifact lock could not be acquired")
    end

    def protocol_file_digest!(object)
      Layout.revalidate_opened!([object], object.identity.fetch(:uid))
      object.handle.rewind
      content = object.handle.read(Layout::MAX_EXTERNAL_INPUT_BYTES + 1)
      object.handle.rewind
      if content.nil? || content.empty? ||
         content.bytesize > Layout::MAX_EXTERNAL_INPUT_BYTES
        fail!("protocol_content", "LAB-004 protocol artifact content is outside its bound")
      end
      Layout.revalidate_opened!([object], object.identity.fetch(:uid))
      Digest::SHA256.digest(content)
    rescue SystemCallError
      fail!("protocol_content", "LAB-004 protocol artifact content could not be read safely")
    end

    def refresh_mutated_directory!(object, uid)
      held = object.handle.stat
      linked = File.lstat(object.path)
      unless held.directory? && !linked.symlink? &&
             held.dev == linked.dev && held.ino == linked.ino &&
             held.uid == uid && linked.uid == uid &&
             (held.mode & 0o777) == object.identity.fetch(:mode) &&
             (linked.mode & 0o777) == object.identity.fetch(:mode)
        fail!("directory_changed", "LAB-004 role directory changed during operation")
      end
      object.identity = Layout.identity(held)
      true
    rescue SystemCallError
      fail!("directory_changed", "LAB-004 role directory changed during operation")
    end

    def compare_stable_file!(before, after, expected_digest, maximum)
      left = before.handle.stat
      right = after.handle.stat
      unless left.file? && right.file? &&
             left.dev == right.dev && left.ino == right.ino &&
             left.uid == right.uid && left.size == right.size &&
             left.mtime.to_f == right.mtime.to_f &&
             (left.mode & 0o777) == (right.mode & 0o777)
        fail!("input_changed", "LAB-004 external input changed during operation")
      end
      content = read_bounded_input!(after, maximum)
      unless Digest::SHA256.digest(content) == expected_digest
        fail!("input_changed", "LAB-004 external input changed during operation")
      end
    rescue SystemCallError
      fail!("input_changed", "LAB-004 external input changed during operation")
    end

    def validate_diagnostic_closure!(boundary, context, opened, uid, completed)
      role = context.roles.fetch("diagnostics")
      expected = boundary.initial_diagnostic_names.dup
      expected << boundary.diagnostic_name if completed
      unless Layout.entries(role, uid).sort == expected.sort
        fail!("diagnostic_inventory", "LAB-004 diagnostic inventory changed during operation")
      end

      start = opened.length
      Layout.validate_diagnostics_role!(role, uid, opened: opened)
      unless Layout.entries(role, uid).sort == expected.sort
        fail!("diagnostic_inventory", "LAB-004 diagnostic inventory changed during operation")
      end
      compare_initial_diagnostics!(boundary, opened.drop(start), role)
      return true unless completed

      unless boundary.diagnostic && boundary.diagnostic_digest &&
             boundary.diagnostic_published?
        fail!("diagnostic_missing", "LAB-004 diagnostic result is missing")
      end
      unless boundary.diagnostic_status == "helper-success"
        fail!("diagnostic_status", "LAB-004 completed operation lacks a success diagnostic")
      end
      current = opened.drop(start).find do |object|
        File.basename(object.path) == boundary.diagnostic_name
      end
      unless current
        fail!("diagnostic_missing", "LAB-004 diagnostic result is missing")
      end
      compare_stable_diagnostic!(
        boundary.diagnostic,
        current,
        boundary.diagnostic_digest
      )
      true
    end

    def compare_stable_diagnostic!(before, after, expected_digest)
      left = before.handle.stat
      right = after.handle.stat
      unless left.file? && right.file? &&
             left.dev == right.dev && left.ino == right.ino &&
             left.uid == right.uid && left.size == right.size &&
             left.mtime.to_f == right.mtime.to_f &&
             (left.mode & 0o777) == 0o400 &&
             (right.mode & 0o777) == 0o400
        fail!("diagnostic_changed", "LAB-004 diagnostic result changed during operation")
      end
      content = read_bounded_file!(after, Layout::MAX_DIAGNOSTIC_FILE_BYTES, false)
      unless Digest::SHA256.digest(content) == expected_digest
        fail!("diagnostic_changed", "LAB-004 diagnostic result changed during operation")
      end
    rescue SystemCallError
      fail!("diagnostic_changed", "LAB-004 diagnostic result changed during operation")
    end

    def cleanup_boundary_diagnostic!(boundary, uid)
      return true unless boundary.diagnostic

      role = boundary.context.roles.fetch("diagnostics")
      Layout.cleanup_unpublished_file!(role, boundary.diagnostic, uid)
      role.identity = Layout.identity(role.handle.stat)
      matching_diagnostic_entries(role, boundary.diagnostic, uid).each do |candidate|
        begin
          Layout.cleanup_unpublished_file!(role, candidate, uid)
          role.identity = Layout.identity(role.handle.stat)
        ensure
          candidate.close
        end
      end
      remaining_names = Layout.entries(role, uid)
      remaining_matches = matching_diagnostic_entries(role, boundary.diagnostic, uid)
      begin
        if remaining_names.include?(boundary.diagnostic_name) || remaining_matches.any?
          fail!("diagnostic_cleanup", "LAB-004 partial diagnostic could not be removed")
        end
      ensure
        remaining_matches.each(&:close)
      end
      role.handle.fsync
      true
    rescue Layout::Error, SystemCallError
      fail!("diagnostic_cleanup", "LAB-004 partial diagnostic could not be removed")
    end

    def matching_diagnostic_entries(role, diagnostic, uid)
      held = diagnostic.handle.stat
      matches = []
      Layout.entries(role, uid).each do |name|
        candidate = Layout.open_regular_file_at!(
          role,
          name,
          uid,
          maximum_size: Layout::MAX_DIAGNOSTIC_FILE_BYTES,
          exact_mode: 0o400,
          allow_empty: true
        )
        stat = candidate.handle.stat
        if stat.dev == held.dev && stat.ino == held.ino
          matches << candidate
        else
          candidate.close
        end
      end
      matches
    rescue StandardError
      matches&.each(&:close)
      raise
    end

    def read_bounded_input!(input, maximum)
      read_bounded_file!(input, maximum, true)
    end

    def read_bounded_file!(input, maximum, reject_empty)
      Layout.revalidate_opened!([input], input.identity.fetch(:uid))
      input.handle.rewind
      content = input.handle.read(maximum + 1)
      input.handle.rewind
      if content.nil? || (reject_empty && content.empty?) || content.bytesize > maximum
        fail!("input_bound", "LAB-004 external input is outside its fixed bound")
      end
      Layout.revalidate_opened!([input], input.identity.fetch(:uid))
      content
    end

    def active_boundary!(boundary)
      unless boundary.is_a?(Boundary) && boundary.active?
        fail!("boundary_inactive", "LAB-004 Host boundary is not active")
      end
      boundary
    end

    def close_boundary!(boundary)
      return unless boundary

      boundary.deactivate!
      boundary.opened.reverse_each(&:close)
      boundary.context.close
    end

    def fail!(code, message)
      raise Error.new(code, message)
    end
  end
end
