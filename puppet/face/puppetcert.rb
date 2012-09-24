
Puppet::Face.define(:puppetcert, '0.0.1') do
  copyright "Puppet Labs", 2012
  license   "Apache 2 license; see COPYING"
  author    "Chris Spence"
  summary "Encrypt and decrypt data using Puppet SSL certs"

  description <<-'EOT'
    This subcommand deals with encrypting data using a specified public SSL 
    key, as configured in hiera.yaml.  The data should be a file, with YAML 
    format data in it, intended to be used as a source of Hiera data.
  EOT

  action(:encrypt) do
    summary "Encrypt a file"
    description <<-'EOT'
      Takes a plain text input and writes out data encrypted using the 
      Openssl libraries
    EOT
    returns <<-'EOT'
      The filename of the now encrypted data with a new suffix, e.g. common.yaml.puppetcert
    EOT
    examples <<-'EOT'
      $ puppet puppetcert encrypt /tmp/common.yaml
      /tmp/common.yaml.puppetcert

      Creates an encrypted file /tmp/common.yaml.puppetcert
    EOT
    notes <<-'EOT'
      The file output by the encrypt action will have the full filename and path
      of the original file.  If you want to use this data for the puppetcert Hiera
      backend, you may have to rename the output file in place as the backend expects
      to find the data for the namespace you are looking up in <namespace>.puppetcert
      This is meant to partner with a Hiera Puppetcert back end which takes care of 
      decrypting the data that you are probably using this Puppet Face to encrypt.

      Check the README for details of configuration - note it uses settings from hiera.yaml
    EOT
    when_invoked do |file,options|

      if File.exist?(File.join(Dir.pwd, file))
        real_file = File.join(Dir.pwd, file)
        cwd = Dir.pwd
      elsif File.exist?(file)
        real_file = file 
        cwd = File.dirname(file)
      else
        raise "could not find file"
      end

      configfile = File.join([File.dirname(Puppet.settings[:config]), "hiera.yaml"])
      raise "could not load #{configfile}" unless File.exist?(configfile)
      config = YAML.load_file(configfile)
      raise "config appears to be empty" unless config

      opensslpath = config[:puppetcert][:ssldir] || '/etc/puppetlabs/puppet/ssl/'
      public_keypath = File.join(opensslpath, config[:puppetcert][:pubkeys] || 'public_keys')
      private_keypath = File.join(opensslpath, config[:puppetcert][:privkeys] || 'private_keys')
      pubkey = config[:puppetcert][:pubkey] || ENV['HOSTNAME']+'.pem'

      unless File.exists?(pubkey)
        sslpubkey = File.join(public_keypath, config[:puppetcert][:cert] || ENV['HOSTNAME']+'.pem')
        raise "Could not find public key #{sslpubkey}" unless File.exists?(sslpubkey)
      else
        sslpubkey = pubkey
      end

      begin
        encryptkey = OpenSSL::PKey::RSA.new File.read sslpubkey
      rescue OpenSSL::PKey::RSAError
        raise "Could not load private key"
      end

      open(real_file) do |plaintext|
        outfile = open(real_file + ".puppetcert",'w')

        until plaintext.eof?
          outfile.write Base64.encode64(encryptkey.public_encrypt(plaintext.read(500))).gsub("\n",'')+"\n"
        end
      end
      return real_file + ".puppetcert"
    end
      
  end

  action(:decrypt) do
    summary "Decrypt a file passed in as an argument"
    description <<-'EOT'
      Takes a ciphertext input and writes out data in the clear using the 
      Openssl libraries
    EOT
    returns "Nothing."
    notes <<-'EOT'
      This is meant to partner with a Hiera Puppetcert back end which takes care of 
      decrypting the data that you are probably using this Puppet Face to encrypt.
      Check the README for details of configuration - note it uses settings from hiera.yaml
    EOT
    examples <<-'EOT'

      $ puppet puppetcert decrypt /tmp/common.puppetcert
      ---
      ntpserver: ntp1.dc1.example.com
      sysadmin: dc1noc@example.com
      moo: different

      $ puppet puppetcert decrypt /tmp/common.puppetcert --writefile /tmp/moo
      /tmp/moo
   
    EOT
    option "--really" do
      summary "do it even with a big file greater than 64KB"
    end
    option "--writefile FILE" do
      summary "output to a file rather than stdout"
    end
    when_invoked do |file,options|

      if File.exist?(File.join(Dir.pwd, file))
        real_file = File.join(Dir.pwd, file)
        cwd = Dir.pwd
      elsif File.exist?(file)
        real_file = file
        cwd = File.dirname(file)
      else
        raise "could not find file"
      end

      if File.size(real_file) > 65536
        raise "big file - alert" unless options[:really]
      end

      configfile = File.join([File.dirname(Puppet.settings[:config]), "hiera.yaml"])
      raise "could not load #{configfile}" unless File.exist?(configfile)
      config = YAML.load_file(configfile)
      raise "config appears to be empty" unless config

      opensslpath = config[:puppetcert][:ssldir] || '/etc/puppetlabs/puppet/ssl/'
      public_keypath = File.join(opensslpath, config[:puppetcert][:pubkeys] || 'public_keys')
      private_keypath = File.join(opensslpath, config[:puppetcert][:privkeys] || 'private_keys')
      privkey = config[:puppetcert][:privkey] || ENV['HOSTNAME']+'.pem'

      unless File.exists?(privkey)
        sslprivkey = File.join(private_keypath, config[:puppetcert][:cert] || ENV['HOSTNAME']+'.pem')
        raise "Could not find privlic key #{sslprivkey}" unless File.exists?(sslprivkey)
      else
        sslprivkey = privkey
      end

      begin
        decryptkey = OpenSSL::PKey::RSA.new File.read sslprivkey
      rescue OpenSSL::PKey::RSAError
        raise "Could not load private key"
      end
      plaintext=[] 
      open(real_file) do |ciphertext|

        if options[:writefile]
          outfile = File.open(options[:writefile],'w')

          until ciphertext.eof?
            outfile.write decryptkey.private_decrypt(Base64.decode64(ciphertext.readline))
          end
        else
          until ciphertext.eof?
            plaintext << decryptkey.private_decrypt(Base64.decode64(ciphertext.readline))
          end
        end
   
      end
      return plaintext.join('') unless options[:writefile]
      return options[:writefile] if options[:writefile]
      
    end
  end
end
