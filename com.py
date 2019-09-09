import random
import blum_blum_shub

class CommitmentScheme(object):
    def __init__(self, oneWayPermutation, hardcorePredicate, securityParameter):
        '''
            oneWayPermutation: int -> int
            hardcorePredicate: int -> {0, 1}
        '''
        self.oneWayPermutation = oneWayPermutation
        self.hardcorePredicate = hardcorePredicate
        self.securityParameter = securityParameter

        # a random string of length `self.securityParameter` used only once per commitment
        self.secret = self.generateSecret()

    def generateSecret(self):
        raise NotImplemented

    def commit(self, x):
        raise NotImplemented

    def reveal(self):
        return self.secret

class BBSBitCommitmentScheme(CommitmentScheme):
    def generateSecret(self):
        # the secret is a random quadratic residue
        self.secret = self.oneWayPermutation(random.getrandbits(self.securityParameter))
        return self.secret

    def commit(self, bit):
        unguessableBit = self.hardcorePredicate(self.secret)
        return (
            self.oneWayPermutation(self.secret),
            unguessableBit ^ bit,  # python xor
        )

class BBSBitCommitmentVerifier(object):
    def __init__(self, oneWayPermutation, hardcorePredicate):
        self.oneWayPermutation = oneWayPermutation
        self.hardcorePredicate = hardcorePredicate

    def verify(self, securityString, claimedCommitment):
        trueBit = self.decode(securityString, claimedCommitment)
        unguessableBit = self.hardcorePredicate(securityString)  # wasteful, whatever
        return claimedCommitment == (
            self.oneWayPermutation(securityString),
            unguessableBit ^ trueBit,  # python xor
        )

    def decode(self, securityString, claimedCommitment):
        unguessableBit = self.hardcorePredicate(securityString)
        return claimedCommitment[1] ^ unguessableBit

class BBSStringCommitmentScheme(CommitmentScheme):
    def __init__(self, numBits, oneWayPermutation, hardcorePredicate, securityParameter=512):
        '''
            A commitment scheme for integers of a prespecified length `numBits`. Applies the
            bit commitment scheme to each bit independently.
        '''
        self.schemes = [BBSBitCommitmentScheme(oneWayPermutation, hardcorePredicate, securityParameter)
                        for _ in range(numBits)]
        super().__init__(oneWayPermutation, hardcorePredicate, securityParameter)

    def generateSecret(self):
        self.secret = [x.secret for x in self.schemes]
        return self.secret

    def commit(self, integer):
        # .zfill(len(self.schemes))
        binaryString = ''.join("0" + (format(ord(x), 'b')) for x in str(integer))
        bits = [int(char) for char in binaryString]
        return [scheme.commit(bit) for scheme, bit in zip(self.schemes, bits)]

class BBSStringCommitmentVerifier(object):
    def __init__(self, numBits, oneWayPermutation, hardcorePredicate):
        self.verifiers = [BBSBitCommitmentVerifier(oneWayPermutation, hardcorePredicate)
                          for _ in range(numBits)]

    def decodeBits(self, secrets, bitCommitments):
        return [v.decode(secret, commitment) for (v, secret, commitment) in
                zip(self.verifiers, secrets, bitCommitments)]

    def verify(self, secrets, bitCommitments):
        return all(
            bitVerifier.verify(secret, commitment)
            for (bitVerifier, secret, commitment) in
            zip(self.verifiers, secrets, bitCommitments)
        )

    def decode(self, secrets, bitCommitments):
        decodedBits = self.decodeBits(secrets, bitCommitments)
        binary = ''.join(str(bit) for bit in decodedBits)
        n = 8;
        binarySets = [binary[i:i+n] for i in range(0, len(binary), n)]
        chars  = [chr(int(charBin, 2)) for charBin in binarySets]
        return ''.join(chars)

if __name__ == "__main__":

    securityParameter = 10
    oneWayPerm = blum_blum_shub.blum_blum_shub(securityParameter)
    hardcorePred = blum_blum_shub.parity
    scheme = BBSStringCommitmentScheme(100, oneWayPerm, hardcorePred)
    verifier = BBSStringCommitmentVerifier(100, oneWayPerm, hardcorePred)

    # secrets = scheme.reveal()
    # print(secrets)

    secrets = [45782, 34856, 9604, 8665, 28702, 37591, 30483, 33756, 9524, 14601, 42310, 6183, 24988, 6204, 3488, 39433, 34766, 46094, 19775, 23875, 40943, 11285, 6183, 24054, 25734, 5223, 6094, 14392, 16113, 43007, 21454, 46200, 17083, 6469, 30745, 20459, 24413, 21196, 16462, 19760, 10746, 42028, 41763, 12019, 42131, 32287, 39827, 4611, 26412, 2678, 38928, 8230, 11994, 1188, 25799, 19533, 30160, 967, 47, 26877, 19551, 12191, 31983, 41621, 22856, 13221, 32849, 29302, 2897, 6893, 5049, 10568, 26756, 1696, 26809, 17845, 47893, 11553, 6838, 31047, 9484, 6599, 34742, 43480, 45195, 31013, 31375, 17183, 24988, 6204, 3488, 39433, 34766, 46094, 19775, 23875, 40943, 11285, 6183, 24054, 25594, 24890, 46352, 16946, 36376, 18046, 45910, 1271, 9684, 42232, 14326, 5629, 1966]
    print(f"SECRETS : {secrets}")

    comm = [(43254, 1), (40858, 1), (30679, 0), (21656, 1), (38196, 0), (35191, 1) , (40405, 1), (17899, 0), (10418, 0), (38617, 1), (31641, 0), (41633, 0), (48182, 0),(9506, 0), (37603, 1), (24082, 1)]
    print(f"COMMITMENTS : {comm}")

    trueString = verifier.decode(secrets, comm)
    print(trueString)
