module GPGME
  class IOCallbacks
    def initialize(@io : IO)
    end

    def read(hook, length : Int) : String
      @io.read_string(length)
    end

    def write(hook, buffer : String, length : Int) : Int
      @io.write(buffer[0...length].to_slice)
      length
    end

    def seek(hook, offset : Int, whence : Int) : Int64
      return @io.pos if offset == 0 && whence == IO::SEEK_CUR
      @io.seek(offset, IO::Seek.new(whence))
      @io.pos
    end
  end
end
