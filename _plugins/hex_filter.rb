module Jekyll
  module HexFilter
    # Converts a decimal integer to a zero-padded uppercase hex string (min 4 chars)
    # Usage: {{ 2026 | dec_to_hex }} => "07EA"
    def dec_to_hex(input)
      n = input.to_i
      hex = n.to_s(16).upcase
      hex.length < 4 ? hex.rjust(4, '0') : hex
    end
  end
end

Liquid::Template.register_filter(Jekyll::HexFilter)
