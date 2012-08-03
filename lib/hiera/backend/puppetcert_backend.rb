class Hiera
    module Backend
        class Puppetcert_backend

        def initialize 
            require 'openssl'
            debug ("Loaded Puppetcert_backend")
        end

        def debug (msg)
            Hiera.debug("[puppetcert_backend]: #{msg}")
        end

        def warn (msg)
            Hiera.warn("[puppetcert_backend]:  #{msg}")
        end


        def lookup(key, scope, order_override, resolution_type)

            debug("Lookup called, key #{key} resolution type is #{resolution_type}")
            answer = Backend.empty_answer(resolution_type)

            opensslpath = Config[:puppetcert][:ssldir] || '/etc/puppetlabs/puppet/ssl/'
            public_keypath = Config[:puppetcert][:pubkeys] || 'public_keys'
            private_keypath = Config[:puppetcert][:privkeys] || 'private_keys'
            privkey = Config[:puppetcert][:cert] || ENV['HOSTNAME']+'.pem'

            ## key is the SSL private key to use to decrypt the data
            sslprivkey = opensslpath + '/' + private_keypath + '/' + privkey
            debug("SSL private key file was #{sslprivkey}")
            Backend.datasources(scope, order_override) do |source|
                puppetcertfile = Backend.datafile(:puppetcert, scope, source, "puppetcert") || next

                plain = decrypt(puppetcertfile, sslprivkey)
                next if !plain
                next if plain.empty?
                debug("SSL cert decrypt returned data")

                data = YAML.load(plain)
                next if !data
                next if data.empty?
                debug ("Data contains valid YAML")

                next unless data.include?(key)
                debug ("Key #{key} found in YAML document, Passing answer to hiera")

                parsed_answer = Backend.parse_answer(data[key], scope)

                begin
                  case resolution_type
                  when :array
                      debug("Appending answer array")
                      answer << parsed_answer
                  when :hash
                      debug("Merging answer hash")
                      answer = parsed_answer.merge answer
                  else
                      debug("Assigning answer variable")
                      answer = parsed_answer
                      break
                  end
                rescue NoMethodError
                    raise Exception, "Resolution type is #{resolution_type} but parsed_answer is a #{parsed_answer.class}"
                end

            end
            return answer
        end
  
        def decrypt(file, sslprivkey)
          
          decryptkey = OpenSSL::PKey::RSA.new File.read sslprivkey
          txtdata=[]
          open(file) do |ciphertext|
            debug("loaded ciphertext: #{file}")
            begin
            until ciphertext.eof?
               txtdata << decryptkey.private_decrypt(Base64.decode64(ciphertext.readline))
            end
          rescue e
            warn("Warning: General exception decrypting file #{e.message}")
          end

          debug("result is a #{txt.class} txt #{txt}")
          return txtdata.join('')
        end
      end
    end
  end
end
