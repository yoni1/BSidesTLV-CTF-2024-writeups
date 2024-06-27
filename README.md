# BSidesTLV-CTF-2024-writeups
This year I sadly didn't have a lot of time to play, so I did just the crypto challenges. I managed to get all four of them for 1400 points. This was enough to reach 23rd place on the scoreboard :)

The writeups are below. Also, I've written some helpful comments inside the solve scripts.

# One Prime Too Many (150 points)

In this challenge, the flag is simply encrypted with 2048-bit RSA. What can you do? Isn't RSA-2048 tough to break? Oops - the key generation uses a single prime instead of a product of two primes for $n$. Well, the difficulty of breaking RSA comes from the fact that it's hard to calculate $\varphi(n)$ (Euler's totient function), since it is equivalent to factoring $n$. But being a prime, $n$'s factorization is trivial, and we know that $\varphi(n) = n - 1$. From this, we basically compute $d$ the same way that is done during key-pair generation: $d$ is the inverse of $e$ modulo $\varphi(n)$. Finally, we recover the flag using $c^d \mod n$.

# Lost Basis Revenge (350 points)

This is a re-do of "[Lost Basis](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/BSidesTLV/2023/crypto/lost-basis)" from BSidesTLV CTF 2023. If you played last year, you may remember there was an unintended solution due to an unplanned bug (left as an exercise 🙃).

The solution to this challenge is presumably the same as the intended solution of last year's challenge. SHA256 seems strong, but XORring the results of SHA256 renders it quite a bit weaker!

Notice that you can request the signature (tag) of a harmless command such as "greet" with whatever number of additional parameters you wish. Therefore, you can XOR as many SHA256 outputs as you wish. You can control which ones go into the XOR and which ones don't. Of course, you can't control what the SHA256 values themselves are going to be -- however, this is still quite powerful.

The XOR operation between a pair of single bits is equivalent to the addition operation in the field $\mathbb F_2$ of two elements. But the full SHA256 hashes are XORred bitwise. This is equivalent to considering these hash values as elements in a 256-dimensional vector space of 256-tuples of bits; that is, the vector space $V := (\mathbb F_2)^{256}$ over $\mathbb F_2$.

It seems we can solve the challenge using linear algebra: All we have to do is to find a set of elements that can be thrown into the tag request, each one representing a vector in $V$, which form a basis. This can be done by collecting a set of 256 such vectors, one by one, and making sure that the set stays linearly independent with each new addition. Once we've done that, with a little help from Gauss, we can form linear combinations to result in any XOR result we wish. And what do we wish? We wish to cancel out the value of `hash_content("greet", "command")` and introduce instead the value of `hash_content("get_flag", "command")`. Once we've done that, we can just ask for a tag for `greet` with the bogus parameters that represent the working linear combination, and just copy that tag over to `get_flag` and solve the challenge.

# MiniDESaster (400 points)

Here we have [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard), a cipher from like 50 years ago (no, seriously 😱), encrypting a message which contains the flag but also a bunch of known plaintext. The number of DES rounds seems to have been reduced from the standard 16 to just 2 in what looks like an LLM-hallucinated (or human-hallucinated?) piece of code (I looked everywhere for "`flexDes`" and couldn't find it, is it a thing?), but which is pretty clear.

It's worth looking at diagrams to follow this one. I haven't drawn any. The diagrams on Wikipedia are pretty good :)

## Step 1: *f*-pairs

Looking at the [Feistel scheme](https://en.wikipedia.org/wiki/Feistel_cipher) of DES, with only two rounds on our hands, it's worth it to write down the expressions for all the half-blocks explicitly:

$$ \begin{align*}
L_1 =& R_0 \\
R_1 =& L_0 \oplus f_1(R_0) \\
\\
L_2 =& R_1 \\
R_2 =& L_1 \oplus f_2(R_1)
\end{align*} $$

By $f_1$ and $f_2$, I mean the DES function $f$ with the scheduled keys for the first and second round, respectively.

Rearranging / plugging in as necessary, we can eliminate $L_1$ and $R_1$ completely (which is great because we can't access them) and we get input and output values for $f_1$ and $f_2$:

$$ \begin{align*}
f_1(R_0) =& L_0 \oplus L_2 \\
f_2(L_2) =& R_0 \oplus R_2
\end{align*} $$

## Step 2: *S*-pairs

Going over the known part of the plaintext, we can get many such pairs and try to discover the round keys. Doing this requires going into [the function $f$ itself](https://en.wikipedia.org/wiki/Data_Encryption_Standard#The_Feistel_(F)_function), which comprises a XOR with the round key, a bunch of 6->4 substitution boxes (S-boxes), and a fixed permutation. With our known pairs, we can work our way from both ends and reach a list of input-output pairs to the S-boxes, where the inputs are XOR an unknown key (but only a 6-bit key for each S-box). With the amount of known plaintext we have, we can collect enough pairs in order to only have one possibility for the round keys.

If this is unclear - read my solution script, it might be clearer than the explanation.

# Curveball (500 points)

This was an exciting challenge, because it reminded me of the Windows vulnerability known as Curveball (a name coined by [Tal Be'ery](https://twitter.com/TalBeerySec), who has [written](https://medium.com/zengo/win10-crypto-vulnerability-cheating-in-elliptic-curve-billiards-2-69b45f2dcab6) [about](https://medium.com/zengo/curveballs-additional-twist-the-certificate-comparison-bug-2698aea445b5) [it](https://medium.com/zengo/hitting-a-curveball-like-a-pro-129c1dca427c)). It is one of my favorite vulnerabilities, and I've also had some chances to write about it, including recently in [Paged Out! #4](https://pagedout.institute/), and used it as an example in a couple of workshops and training exercises (closed source, sorry).

In the Windows Curveball vulnerability, essentially what you had (at least from a math point of view) was the ability to view an elliptic curve public key from a different point of view: Relative to another generator of your choice, instead of the original curve generator. The CTF Curveball challenge is not the same -- but not too different either! In this challenge, we have an implementation of [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) on your choice of two standard curves: Brainpool BP-384 or NIST P-384. You can get the flag if you're able to demonstrate your ability to sign a particular message, `"I really wanna flag"` (well, technically, you need to sign the SHA-384 hash of this message, but ok). The server generates a key pair for you to use, but then it throws the private key in the trash.

Discovering the private key is out of the question. These are both standard curves used in ECDSA, considered to be strong, so finding out the private key given the public key comes down to solving the Elliptic Curve Discrete Logarithm Problem (ECDLP) on those curves. Yeeeeah, no.

One can immediately notice that you can generate a key on one curve and then apply it to the other curve. The bug here is that the server is missing a check that the public key, a curve point, is *actually on the curve*. Since the curve equation is $y^2 = ...$ (and we're working over a field), every value of $x$ can have exactly two possible values of $y$; therefore, a point $(x, y)$ on one curve is *extremely unlikely* to also be on the other curve. By doing this, we get to do elliptic curve math with a point that has "fallen off the curve"; in other words, we're going to do a variation of what's known as an "invalid curve attack".

## If a point falls off an elliptic curve, does it make a sound?

Let's say we're working with some elliptic curve,
$$y^2 \equiv x^3 + ax + b \pmod p$$
and some point $(x_0, y_0)$ is **NOT** on the curve. Where is it, then? What happens when we apply curve operations to it?

Those curve operations are:
* Adding two distinct points $P$ and $Q$.
* Doubling a point $P$ (basically adding it to itself).
* Multiplying a point $P$ by a scalar $k$ (basically adding it to itself $k$ times).

Multiplying by a scalar doesn't involve any curve math, just the [double-and-add algorithm](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add). Let's focus on the addition and doubling.

Implementations of point addition and doubling (including the implementation in the challenge) use the values of the input points' coordinates, the curve parameter $a$, and the curve modulo $p$. Notice that they do **NOT** use the parameter $b$. Therefore, they might as well be curve operations on another curve, whose only difference from our curve is it has a different value of $b$, and which contains the point $(x_0, y_0)$. But does such a curve exist? Of course! $b$ is a free coefficient, so if you calculate

$$b' :\equiv y_0^2 - x_0^3 - ax_0 \pmod p$$

then you get an alternate curve

$$y^2 \equiv x^3 + ax + b' \pmod p$$

which satisfies those conditions.

## Change the place, change the luck

The order of an elliptic curve, that is -- the number of points on it, has a lot of importance due to the curve's group structure. Due to a basic group-theoretic fact - [Lagrange's theorem](https://en.wikipedia.org/wiki/Lagrange%27s_theorem_(group_theory)), multiplying any point on the curve by the curve's order will send it to the neutral group element - the point at infinity, $\mathcal O$.

What is the order of an elliptic curve? Unlike simpler groups (like integers mod $n$, where it is given by Euler's totient function with all its nice properties), in elliptic curves there is not a lot of "control", so to speak, over the order of the curve. We do have [Hasse's theorem](https://en.wikipedia.org/wiki/Hasse%27s_theorem_on_elliptic_curves), which tells us that the order can't be that far off from $p$, the modulo, but it doesn't have to be a specific value.

This is great for us - it means that if we change the curve, we are likely to get a different curve order. Fortunately, it is easy to compute the curve's order using [Schoof's algorithm](https://en.wikipedia.org/wiki/Schoof%27s_algorithm) or the slightly more modern [SEA algorithm](https://en.wikipedia.org/wiki/Schoof%E2%80%93Elkies%E2%80%93Atkin_algorithm). In SageMath, it is implemented in [`EllipticCurve.order`](https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/ell_point.html#sage.schemes.elliptic_curves.ell_point.EllipticCurvePoint_field.order).

## Using the changed order to obliterate ECDSA

Let's take a look at the main formula used for ECDSA verification:

$$R = \frac z s G + \frac r s Q$$

where $G$ is the curve generator, $Q$ is the public key, $z$ is the hash of the message to be signed, and $r, s$ are signature parameters; $r$ is compared to the $x$ coordinate of $R$ to verify the signature. Since the order of the curve is supposed to be $n$, all of the factors are modulo $n$.

In our case, we can get $Q$ to be on a different curve that has a different order other than $n$, let's call it $n_Q$.

What if in fact $n_Q < n$? If we can get $Q$ to be multiplied by $n_Q$, even after modulo $n$ it will still retain its value $n_Q$. Then, multiplied by $Q$, it will actually vanish to infinity!

This can be done by an attacker by choosing $s^{-1} \equiv n_Q \pmod n$. Then, we are left with:
$$R = \frac z s G + \mathcal O = \frac z s G$$
This equation no longer refers to $r$ and can be computed by an attacker, so all the attacker has to do is calculate this $R$ and then set $r$ to be its $x$ coordinate.
