// DEBUG TEMPORARY: a bounded numeric execution schema, not arbitrary native text.
private enum ADIExecutionWire {
    static func valid(_ text: String) -> Bool {
        guard text.utf8.count <= 1320, text.utf8.allSatisfy({ $0 < 128 }) else { return false }
        let fields = text.split(separator: ";", omittingEmptySubsequences: false)
        guard (5...23).contains(fields.count), fields[0] == "x1" else { return false }
        let hashes = fields[1].split(separator: ",", omittingEmptySubsequences: false)
        guard hashes.count == 3, hashes[0] == "H" else { return false }
        for hash in hashes.dropFirst() {
            guard hash == "0" || (hash.utf8.count == 64 && hash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })) else { return false }
        }
        var counts: [String: Int] = [:]
        for (position, field) in fields.enumerated() where position >= 2 {
            let values = field.split(separator: ",", omittingEmptySubsequences: false)
            guard let tag = values.first else { return false }
            let parts = values.dropFirst()
            let nums = parts.compactMap { UInt32($0) }
            guard nums.count == parts.count, zip(parts, nums).allSatisfy({ String($0.1) == String($0.0) }) else { return false }
            func location(_ a: Int) -> Bool { nums[a] <= 2 && (nums[a] != 0 || nums[a+1] == 0) }
            switch tag {
            case "S": guard position == 2, nums.count == 7, nums[0] <= 31, nums[5] <= 3, nums[6] <= 31 else { return false }
            case "F", "L": guard position == (tag == "F" ? 3 : 4), nums.count == 4, location(0), location(2) else { return false }
            case "P", "R":
                guard position >= 5, nums.count == 2, location(0) else { return false }
                counts[String(tag), default: 0] += 1
                guard counts[String(tag), default: 0] <= (tag == "P" ? 6 : 4) else { return false }
            case "I":
                guard position >= 5, nums.count == 7, nums[0] <= 5, nums[1] <= 44,
                      nums[2] <= 8192, location(3), nums[5] <= 4, nums[6] <= 4096 else { return false }
                counts["I", default: 0] += 1
                guard counts["I", default: 0] <= 8 else { return false }
            default: return false
            }
        }
        return fields[2].hasPrefix("S,") && fields[3].hasPrefix("F,") && fields[4].hasPrefix("L,")
    }
    static func trim(_ text: String) -> String? {
        guard valid(text) else { return nil }
        var rows = text.components(separatedBy: ";")
        guard let index = rows.indices.first(where: { rows[$0].hasPrefix("I,") })
            ?? rows.indices.first(where: { rows[$0].hasPrefix("P,") })
            ?? rows.indices.first(where: { rows[$0].hasPrefix("R,") }) else { return nil }
        let removed = rows.remove(at: index)
        var summary = rows[2].components(separatedBy: ",")
        summary[1] = String((UInt32(summary[1]) ?? 0) | 16)
        if removed.hasPrefix("I,") { summary[4] = String(min(UInt64(UInt32.max), (UInt64(summary[4]) ?? 0) + 1)) }
        rows[2] = summary.joined(separator: ",")
        return rows.joined(separator: ";")
    }
}
