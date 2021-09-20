package sshkey

/*
ecdsa-sha2-nistp256
ecdsa-sha2-nistp384
ecdsa-sha2-nistp521
ssh-ed25519
ssh-dss
ssh-rsa
sk-ssh-ed25519@openssh.com
sk-ecdsa-sha2-nistp256@openssh.com
*/

func isKey(s []rune) bool {
	if len(s) < 7 { // ssh-dss
		return false
	}
	switch s[0] {
	case 'e':
		switch {
		case !runeSliceHasPrefix(s[1:], []rune("cdsa-sha2-nistp")):
			return false
		case runeSliceHasPrefix(s[16:], []rune("256")):
			return true
		case runeSliceHasPrefix(s[16:], []rune("384")):
			return true
		case runeSliceHasPrefix(s[16:], []rune("521")):
			return true
		default:
			return false
		}
	case 's':
		if !runeSliceHasPrefix(s[1:], []rune("k-")) {
			switch {
			case !runeSliceHasPrefix(s[1:], []rune("sh-")):
				return false
			case runeSliceHasPrefix(s[4:], []rune("ed25519")):
				return true
			case runeSliceHasPrefix(s[4:], []rune("dss")):
				return true
			case runeSliceHasPrefix(s[4:], []rune("rsa")):
				return true
			default:
				return false
			}
		} else {
			switch {
			case runeSliceHasPrefix(s[3:], []rune("ssh-ed25519@openssh.com")):
				return true
			case runeSliceHasPrefix(s[3:], []rune("ecdsa-sha2-nistp256@openssh.com")):
				return true
			default:
				return false
			}
		}
	default:
		return false
	}
}
