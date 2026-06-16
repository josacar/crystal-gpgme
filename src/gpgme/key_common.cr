module GPGME
  module KeyCommon
    abstract def revoked? : Bool
    abstract def expired? : Bool
    abstract def disabled? : Bool
    abstract def invalid? : Bool
    abstract def can_encrypt? : Bool
    abstract def can_sign? : Bool
    abstract def can_certify? : Bool
    abstract def can_authenticate? : Bool
    abstract def secret? : Bool

    def trust : Symbol?
      return :revoked if revoked?
      return :expired if expired?
      return :disabled if disabled?
      return :invalid if invalid?
      nil
    end

    def capability : Array(Symbol)
      caps = [] of Symbol
      caps << :encrypt if can_encrypt?
      caps << :sign if can_sign?
      caps << :certify if can_certify?
      caps << :authenticate if can_authenticate?
      caps
    end

    def usable_for?(purposes : Symbol | Array(Symbol)) : Bool
      purposes = [purposes] if purposes.is_a?(Symbol)
      return false if trust
      (purposes - capability).empty?
    end
  end
end
