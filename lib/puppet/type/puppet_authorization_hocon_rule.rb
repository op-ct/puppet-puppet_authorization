# frozen_string_literal: true

Puppet::Type.newtype(:puppet_authorization_hocon_rule) do
  ensurable do
    defaultvalues
    defaultto :present
  end

  newparam(:name, namevar: true) do
    desc 'An arbitrary name used as the identity of the resource.'
  end

  newparam(:path) do
    desc 'The file Puppet will ensure contains the specified setting.'
    validate do |value|
      # rubocop:disable Style/IfUnlessModifier
      unless (Puppet.features.posix? && value =~ %r{^/}) || (Puppet.features.microsoft_windows? && (value =~ %r{^.:/} || value =~ %r{^//[^/]+/[^/]+}))
        raise(Puppet::Error, "File paths must be fully qualified, not '#{value}'")
      end
      # rubocop:enable Style/IfUnlessModifier
    end
  end

  newproperty(:value, array_matching: :all) do
    desc 'The value of the setting to be defined.'

    validate do |val|
      raise "Value must be a hash but was #{value.class}" unless val.is_a?(Hash)

      validate_acl(val)
    end

    def validate_acl(val)
      %w[allow deny].each do |rule|
        next unless val.key?(rule)

        case val[rule]
        when Hash
          validate_acl_hash(val[rule], rule)
        when Array
          hashes = val[rule].select { |cur_rule| cur_rule.is_a?(Hash) }
          hashes.each { |cur_rule| validate_acl_hash(cur_rule, rule) }
        end
      end
    end

    def validate_acl_hash(val, rule)
      allowed_keys = %w[certname extensions]
      unknown_keys = val.reject { |k, _| allowed_keys.include?(k) }
      raise "Only one of 'certname' and 'extensions' are allowed keys in a #{rule} hash. Found '#{unknown_keys.keys.join(', ')}'." unless unknown_keys.empty?
      raise "Only one of 'certname' and 'extensions' are allowed keys in a #{rule} hash." unless val.length == 1
    end

    def insync?(_is)
      # make sure all passed values are in the file
      values = provider.value.flatten
      Array(@resource[:value]).all? { |v| values.include?(v) }
    end

    def change_to_s(current, new)
      real_new = []
      real_new << current
      real_new << new
      real_new.flatten!
      real_new.uniq!
      "value changed [#{Array(current).flatten.join(', ')}] to [#{real_new.join(', ')}]"
    end
  end

  validate do
    message = ''
    message += 'path is a required parameter. ' if original_parameters[:path].nil?
    message += 'value is a required parameter unless ensuring a setting is absent.' if original_parameters[:value].nil? && self[:ensure] != :absent
    raise(Puppet::Error, message) if message != ''
  end
end
