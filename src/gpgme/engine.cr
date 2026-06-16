module GPGME
  module Engine
    extend self

    def check_version(proto : UInt32) : Bool
      err = LibGPGME.engine_check_version(proto)
      GPGME.error_to_exception(err).nil?
    end

    def info : Array(EngineInfo)
      infos = [] of EngineInfo
      err = LibGPGME.get_engine_info(out info)
      exc = GPGME.error_to_exception(err)
      raise exc if exc

      ptr = info
      while ptr
        infos << EngineInfo.new(
          LibGPGME.cgpgme_engine_info_protocol(ptr).to_u32,
          GPGME.nullable_string(LibGPGME.cgpgme_engine_info_file_name(ptr)),
          GPGME.nullable_string(LibGPGME.cgpgme_engine_info_version(ptr)),
          GPGME.nullable_string(LibGPGME.cgpgme_engine_info_req_version(ptr)),
          GPGME.nullable_string(LibGPGME.cgpgme_engine_info_home_dir(ptr))
        )
        ptr = LibGPGME.cgpgme_engine_info_next(ptr)
      end
      infos
    end

    def set_info(proto : UInt32, file_name : String?, home_dir : String?) : Nil
      err = LibGPGME.set_engine_info(
        proto.to_i32,
        file_name ? file_name.to_unsafe : Pointer(LibC::Char).null,
        home_dir ? home_dir.to_unsafe : Pointer(LibC::Char).null
      )
      exc = GPGME.error_to_exception(err)
      raise exc if exc
    end

    def home_dir=(home_dir : String)
      Dir.mkdir_p(home_dir)
      current = info.first
      set_info(current.protocol, current.file_name, home_dir)
    end

    def dirinfo(what : String) : String?
      GPGME.nullable_string(LibGPGME.get_dirinfo(what.to_unsafe))
    end
  end
end
