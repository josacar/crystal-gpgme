module GPGME
  class Data
    BLOCK_SIZE = 4096

    getter handle : LibGPGME::Data

    def self.new : Data
      empty!
    end

    def self.new(object : Data | IO | String | Int32 | Nil) : Data
      case object
      when Data   then object
      when String then from_str(object)
      when Int    then from_fd(object)
      when IO     then from_io(object)
      else             empty!
      end
    end

    def self.new(object : Nil) : Data
      empty!
    end

    def self.new(object : Data) : Data
      object
    end

    def self.new(object : String) : Data
      from_str(object)
    end

    def self.new(object : Int) : Data
      from_fd(object)
    end

    def self.new(object : IO) : Data
      from_io(object)
    end

    def self.empty! : Data
      LibGPGME.data_new(out dh)
      new(dh)
    end

    def self.from_str(string : String) : Data
      LibGPGME.data_new_from_mem(out dh, string.to_unsafe, string.bytesize, 1)
      new(dh)
    end

    def self.from_io(io : IO) : Data
      # For IO objects we create a memory-backed buffer pre-filled with the
      # available content.  This is the simplest portable approach until a
      # full callback-based IO adapter is implemented.
      data = empty!
      io.each_byte do |byte|
        data.write_byte(byte)
      end
      data.seek(0, IO::Seek::Set)
      data
    end

    def self.from_fd(fd : Int) : Data
      LibGPGME.data_new_from_fd(out dh, fd)
      new(dh)
    end

    def initialize(@handle : LibGPGME::Data)
    end

    def finalize
      LibGPGME.data_release(@handle)
    end

    def read(length : Int? = nil) : String
      if length
        buffer = Bytes.new(length)
        n = LibGPGME.data_read(@handle, buffer, buffer.size)
        if n < 0
          raise IO::Error.new("GPGME::Data read error")
        end
        String.new(buffer[0, n])
      else
        buf = Bytes.new(BLOCK_SIZE)
        result = IO::Memory.new
        loop do
          n = LibGPGME.data_read(@handle, buf, buf.size)
          if n < 0
            raise IO::Error.new("GPGME::Data read error")
          elsif n == 0
            break
          else
            result.write(buf[0, n])
          end
        end
        result.to_s
      end
    end

    def write(buffer : String, length : Int = buffer.bytesize) : Int
      write(buffer.to_slice[0, length])
    end

    def write(buffer : Bytes) : Int
      n = LibGPGME.data_write(@handle, buffer, buffer.size)
      raise IO::Error.new("GPGME::Data write error") if n < 0
      n.to_i
    end

    def write_byte(byte : UInt8) : Nil
      write(Bytes[byte])
    end

    def seek(offset : Int, whence : IO::Seek = IO::Seek::Set) : Int64
      LibGPGME.data_seek(@handle, offset.to_i64, whence.value)
    end

    def encoding : UInt32
      LibGPGME.data_get_encoding(@handle)
    end

    def encoding=(enc : UInt32)
      err = LibGPGME.data_set_encoding(@handle, enc)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      enc
    end

    def file_name : String?
      ptr = LibGPGME.data_get_file_name(@handle)
      ptr.null? ? nil : String.new(ptr)
    end

    def file_name=(name : String)
      err = LibGPGME.data_set_file_name(@handle, name.to_unsafe)
      exc = GPGME.error_to_exception(err)
      raise exc if exc
      name
    end

    def to_s : String
      pos = seek(0, IO::Seek::Current)
      begin
        seek(0, IO::Seek::Set)
        read
      ensure
        seek(pos.to_i, IO::Seek::Set)
      end
    end

    def to_slice : Bytes
      pos = seek(0, IO::Seek::Current)
      begin
        seek(0, IO::Seek::Set)
        buf = Bytes.new(BLOCK_SIZE)
        result = IO::Memory.new
        loop do
          n = LibGPGME.data_read(@handle, buf, buf.size)
          if n < 0
            raise IO::Error.new("GPGME::Data read error")
          elsif n == 0
            break
          else
            result.write(buf[0, n])
          end
        end
        result.to_slice
      ensure
        seek(pos.to_i, IO::Seek::Set)
      end
    end
  end
end
