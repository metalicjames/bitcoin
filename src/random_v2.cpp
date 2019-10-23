#include <random>

#include <crypto/sha512.h>
#include <support/cleanse.h>
#include <sync.h>

#define PRNG_STATE_LEN 32

class RNGState_v2 {
    Mutex m_mutex;
    /* The RNG state consists of 256 bits of entropy, taken from the output of
     * one operation's SHA512 output, and fed as input to the next one.
     * Carrying 256 bits of entropy should be sufficient to guarantee
     * unpredictability as long as any entropy source was ever unpredictable
     * to an attacker. 
     */
    unsigned char m_state[PRNG_STATE_LEN] GUARDED_BY(m_mutex) = {0};
    uint64_t m_counter GUARDED_BY(m_mutex) = 0;
    bool m_strongly_seeded GUARDED_BY(m_mutex) = false;

public:
    class NoEntropySourceException : public std::exception {
        virtual const char* what() const throw() {
            return "No suitable entropy source could be found";
        }
    };

    class OutOfEntropyException : public std::exception {
        virtual const char* what() const throw() {
            return "The entropy source reports it has insufficient entropy";
        }
    };

    class NotSeededException : public std::exception {
        virtual const char* what() const throw() {
            return "The PRNG has not been properly seeded";
        }
    };

    RNGState_v2() {
        // Try RDSEED first to seed the PRNG.
        // Since we are seeding a PRNG with this value we use RDSEED instead of
        // RDRAND. See https://software.intel.com/en-us/blogs/2012/11/17/the-difference-between-rdrand-and-rdseed.
        std::unique_ptr<std::random_device> rd(new std::random_device("rdseed"));

        if(rd->entropy() < sizeof(unsigned int)) {
            // If RDSEED is not available try /dev/random blocking randomness.
            rd.reset(new std::random_device("/dev/random"));

            if(rd->entropy() < sizeof(unsigned int)) {
                // Try for kernel PRNG randomness.
                rd.reset(new std::random_device("/dev/urandom"));

                if(rd->entropy() < sizeof(unsigned int)) {
                    // Last resort: try the default of this standard library.
                    // On Windows this would be the bcrypt system library.
                    rd.reset(new std::random_device("default"));

                    if(rd->entropy() < sizeof(unsigned int)) {
                        // We have nothing so it is not safe to use this PRNG.
                        throw NoEntropySourceException();
                    }
                }
            }
        }

        LOCK(m_mutex);
        for(unsigned int i = 0; i < PRNG_STATE_LEN / sizeof(unsigned int); i++) {
            // Check if there is still a good entropy source to request more
            // random numbers from.
            if(rd->entropy() < sizeof(unsigned int)) {
                throw OutOfEntropyException();
            }

            // Get a random number from the random_device. 
            unsigned int random_value = (*rd)();

            // Copy it into the PRNG state. 
            memcpy(&m_state[i*sizeof(unsigned int)], 
                   &random_value, 
                   sizeof(unsigned int));

            // Clean the temporary variable used to store the random number.
            memory_cleanse(&random_value, sizeof(unsigned int));
        }

        // The PRNG has been successfully seeded so set the flag to allow 
        // MixExtract to work. 
        m_strongly_seeded = true;
    }

    ~RNGState_v2() {
        memory_cleanse(m_state, sizeof(m_state));
        memory_cleanse(&m_counter, sizeof(m_counter));
    }

    /*
     * Extract up to PRNG_STATE_LEN bytes of entropy from the RNG state.
     */
    void MixExtract(unsigned char* out, const size_t num) {
        assert(num <= PRNG_STATE_LEN);
        unsigned char buf[PRNG_STATE_LEN*2];
        CSHA512 hasher;
        static_assert(sizeof(buf) == CSHA512::OUTPUT_SIZE, "Buffer needs to have hasher's output size");
  
        LOCK(m_mutex);

        if(!m_strongly_seeded) {
            throw NotSeededException();
        }

        // Write the current state of the RNG into the hasher
        hasher.Write(m_state, PRNG_STATE_LEN);
        // Write a new counter number into the state
        hasher.Write((const unsigned char*)&m_counter, sizeof(m_counter));
        ++m_counter;
        // Finalize the hasher
        hasher.Finalize(buf);
        // Store the last PRNG_STATE_LEN bytes of the hash output as new RNG state.
        memcpy(m_state, buf + PRNG_STATE_LEN, PRNG_STATE_LEN);

        // Copy (up to) the first PRNG_STATE_LEN bytes of the hash output as output.
        assert(out != nullptr);
        memcpy(out, buf, num);
        
        // Best effort cleanup of internal state
        hasher.Reset();
        memory_cleanse(buf, sizeof(buf));
    }
};