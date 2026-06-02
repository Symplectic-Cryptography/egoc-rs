(* Hiding.ec — lattice (SHADOW-SIS-FIX / BDLOP) hiding reduces to Decision-MLWE.
   SKELETON: the hybrid argument's core step is `admit`ed (see comment). *)

require import AllCore Distr DBool.

(* ---- ambient ring/module parameters (abstract) ------------------------- *)
type Rq.                          (* R_q = Z_q[X]/(X^256+1) *)
op zeroR : Rq.
op ( + ) : Rq -> Rq -> Rq.
op ( * ) : Rq -> Rq -> Rq.

op kbind : int.   op kmsg : int.   op lrand : int.
axiom bdlop_shape : lrand > kbind + kmsg.   (* the SHADOW-SIS-FIX invariant *)

type vecR = Rq list.              (* module vectors *)
op matvec : Rq list list -> vecR -> vecR.   (* A · r *)
op vadd   : vecR -> vecR -> vecR.

(* short randomness distribution (uniform [-eta,eta]^{lrand·N}) *)
op dShort : vecR distr.
axiom dShort_ll : is_lossless dShort.

(* public matrices, expanded from a seed *)
op A1 : Rq list list.   op A2 : Rq list list.

(* ---- the commitment ----------------------------------------------------- *)
op commit (m r : vecR) : vecR * vecR =
  (matvec A1 r, vadd (matvec A2 r) m).        (* (c1, c2) = (A1 r, A2 r + m) *)

(* ---- Decision-MLWE assumption (declared, not proven) -------------------- *)
module type MLWE_Dist = {
  proc distinguish (samples : (Rq list list * vecR)) : bool
}.
(* Adv^{MLWE} = |Pr[real]-Pr[uniform]| ; assumed negligible. *)
op eps_mlwe : real.
axiom mlwe_hard (D <: MLWE_Dist) : true. (* placeholder for the formal advantage bound *)

(* ---- Hiding game -------------------------------------------------------- *)
module type Adv = {
  proc choose () : vecR * vecR          (* m0, m1 *)
  proc guess  (c : vecR * vecR) : bool
}.

module Hiding (A : Adv) = {
  proc main () : bool = {
    var m0, m1, b, r, c, b';
    (m0, m1) <@ A.choose();
    b  <$ {0,1};
    r  <$ dShort;
    c  <- commit (if b then m1 else m0) r;
    b' <@ A.guess(c);
    return (b = b');
  }
}.

(* ---- Reduction: Hiding adversary -> MLWE distinguisher ------------------ *)
(* Standard BDLOP18 hybrid: replace (A1 r, A2 r) by a uniform pair using one
   MLWE sample on the stacked matrix [A1;A2]; then c2 = uniform + m hides m
   information-theoretically. The width condition lrand > kbind+kmsg
   (`bdlop_shape`) is what makes [A1;A2]·r a genuine MLWE instance. *)
lemma hiding_reduces_to_mlwe (A <: Adv) &m :
  `| Pr[Hiding(A).main() @ &m : res] - 1%r/2%r | <= eps_mlwe.
proof.
  (* 1. game-hop: commit's (c1,c2) -> (u1, u2 + m) with (u1,u2) uniform,
        justified by one Decision-MLWE step on [A1;A2] (uses bdlop_shape). *)
  (* 2. in the hopped game c2 = uniform + m is independent of b -> Pr = 1/2. *)
  (* 3. the hop's distance is exactly Adv^{MLWE} <= eps_mlwe. *)
  admit. (* FILL: the two-step hybrid; discharge via `mlwe_hard` applied to the
            constructed distinguisher B(A). The reduction B forwards A's commit
            using its MLWE challenge as (c1,c2-m). *)
qed.
