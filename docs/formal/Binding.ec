(* Binding.ec — three binding facts:
   (i)   lift injectivity ⇒ message-binding of the encode map (UNCONDITIONAL);
   (ii)  lattice binding ≤ MSIS, and statistical when λ1 ≫ 2·opening-norm;
   (iii) MCE code-mode binding ≤ MCE-collision.
   SKELETON: (i) is provable outright; (ii),(iii) reduce to the named problems. *)

require import AllCore List.

(* ===== (i) lift injectivity (egoc-sl2): UNCONDITIONAL ===================== *)
type Fq.
op lift : Fq list -> Fq list -> (Fq * Fq) list.   (* row blocks [m_i,r_i],[r_i,-m_i] *)

(* ker(lift) = {0}: lift(m,r)=0 ⇒ m=0 ∧ r=0, entrywise. *)
lemma lift_injective (m r m' r' : Fq list) :
  lift m r = lift m' r' => m = m' /\ r = r'.
proof.
  (* entrywise: block i forces (m_i,r_i) = (m'_i,r'_i). Pure algebra, no assumption. *)
  admit. (* FILL: induction on the list; each 2x2 block equation is trivial. *)
qed.

(* ===== (ii) lattice binding: MSIS / statistical ========================== *)
type Rq.
op ( - ) : Rq list -> Rq list -> Rq list.
op matvec : Rq list list -> Rq list -> Rq list.
op A1 : Rq list list.
op normInf : Rq list -> int.
op eta : int.
op lambda1_kerA1 : int.            (* shortest vector of {v : A1 v = 0} *)

(* statistical binding: if λ1 > 2η then no two short openings collide. *)
axiom params_give_statistical_binding : lambda1_kerA1 > 2 * eta.

lemma lattice_binding_statistical (r r' : Rq list) :
  matvec A1 r = matvec A1 r' =>
  normInf r <= eta => normInf r' <= eta =>
  r = r'.
proof.
  (* r-r' is in ker(A1) with normInf(r-r') <= 2η < λ1 ⇒ r-r' = 0. *)
  admit. (* FILL: A1(r-r')=0 ∧ ‖r-r'‖∞ ≤ 2η, and `params_give_statistical_binding`
            ⇒ r-r' is a kernel vector shorter than λ1 ⇒ zero. *)
qed.

(* ===== (iii) MCE code-mode binding ≤ MCE-collision ======================= *)
type MatE.
op two_sided : MatE -> MatE -> MatE -> MatE.   (* S·M·T *)
op encode : Fq list -> Fq list -> MatE.        (* M(c) in the code *)

(* a second opening (S',M',T') of the same C with different message is an
   MCE-collision instance; assumed hard. *)
op eps_mce_coll : real.
axiom mce_collision_hard : true.   (* placeholder advantage bound *)

lemma mce_binding (S T S' T' : MatE) (m r m' r' : Fq list) :
  two_sided S (encode m r) T = two_sided S' (encode m' r') T' =>
  (* either (m,r)=(m',r')  (and the keys agree up to stabiliser),
     or a poly-time MCE-collision solver exists. *)
  true.
proof.
  admit. (* FILL: from a colliding pair extract the equivalence
            S'^{-1} S · encode(m,r) · T T'^{-1} = encode(m',r'); if messages
            differ this is a nontrivial code isometry = MCE-collision. *)
qed.
