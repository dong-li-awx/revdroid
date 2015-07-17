package com.lazarusx.revdroid.analyzer;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import soot.Body;
import soot.G;
import soot.IntType;
import soot.Local;
import soot.LongType;
import soot.NullType;
import soot.RefType;
import soot.Timers;
import soot.Trap;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.ArrayRef;
import soot.jimple.AssignStmt;
import soot.jimple.BinopExpr;
import soot.jimple.CastExpr;
import soot.jimple.DivExpr;
import soot.jimple.FieldRef;
import soot.jimple.InstanceFieldRef;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.LongConstant;
import soot.jimple.NewArrayExpr;
import soot.jimple.NewExpr;
import soot.jimple.NewMultiArrayExpr;
import soot.jimple.NopStmt;
import soot.jimple.NullConstant;
import soot.jimple.RemExpr;
import soot.options.Options;
import soot.toolkits.scalar.LocalDefs;
import soot.util.Chain;

public class RevDroidDeadAssignmentEliminator{
	private static RevDroidDeadAssignmentEliminator instance = null;

	protected RevDroidDeadAssignmentEliminator() {
	}
	
	public static RevDroidDeadAssignmentEliminator v() {
		if (instance == null) {
			instance = new RevDroidDeadAssignmentEliminator();
		}
		return instance;
	}

	/**
	 * Eliminates dead code in a linear fashion.  Complexity is linear 
	 * with respect to the statements.
	 *
	 * Does not work on grimp code because of the check on the right hand
	 * side for side effects. 
	 * 
	 * On top of DeadAssignmentEliminator, but does not check invoke
	 */
	public void transform(Body b)
	{
		if (Options.v().verbose()) {
			G.v().out.println("[" + b.getMethod().getName() + "] Eliminating dead code...");
		}
		
		if (Options.v().time()) {
			Timers.v().deadCodeTimer.start();
		}

		Chain<Unit> units = b.getUnits();
		Deque<Unit> q = new ArrayDeque<Unit>(units.size());

		// Make a first pass through the statements, noting 
		// the statements we must absolutely keep. 

		boolean isStatic = b.getMethod().isStatic();
		boolean allEssential = true;
		boolean checkInvoke = false;
				
		Local thisLocal = null;

		for (Iterator<Unit> it = units.iterator(); it.hasNext(); ) {
			Unit s = it.next();
			boolean isEssential = true;
			
			if (s instanceof NopStmt) {
				// Hack: do not remove nop if is is used for a Trap
				// which is at the very end of the code.
				boolean removeNop = it.hasNext();
				
				if (!removeNop) { 
					removeNop = true;
					for (Trap t : b.getTraps()) {
						if (t.getEndUnit() == s) {
							removeNop = false;
							break;
						}
					}
				}
				
				if (removeNop) {
					it.remove();
					continue;
				}
			}
			else if (s instanceof AssignStmt) {
				AssignStmt as = (AssignStmt) s;
				
				Value lhs = as.getLeftOp();
				Value rhs = as.getRightOp();
				
				// Stmt is of the form a = a which is useless
				if (lhs == rhs && lhs instanceof Local) {
					it.remove();
					continue;
				}
				
				if (lhs instanceof Local &&
					(((Local) lhs).getName().startsWith("$")
						|| lhs.getType() instanceof NullType))
				{
				
					isEssential = false;
					
					if ( !checkInvoke ) {
						checkInvoke |= as.containsInvokeExpr();
					}
					
					if (rhs instanceof CastExpr) {
						// CastExpr          : can trigger ClassCastException, but null-casts never fail
						CastExpr ce = (CastExpr) rhs;
						Type t = ce.getCastType();
						Value v = ce.getOp();
						isEssential = !(t instanceof RefType && v == NullConstant.v());
					}
					else if (rhs instanceof InvokeExpr || 
					    rhs instanceof ArrayRef || 
					    rhs instanceof NewExpr ||
					    rhs instanceof NewArrayExpr ||
					    rhs instanceof NewMultiArrayExpr )
					{
					   // ArrayRef          : can have side effects (like throwing a null pointer exception)
					   // InvokeExpr        : can have side effects (like throwing a null pointer exception)
					   // NewArrayExpr      : can throw exception
					   // NewMultiArrayExpr : can throw exception
					   // NewExpr           : can trigger class initialization					   
						isEssential = true;
					}
					else if (rhs instanceof FieldRef) {
						// Can trigger class initialization
						isEssential = true;
					
						if (rhs instanceof InstanceFieldRef) {
							InstanceFieldRef ifr = (InstanceFieldRef) rhs;						
			
							if ( !isStatic && thisLocal == null ) {
								thisLocal = b.getThisLocal();
							}
												
							// Any InstanceFieldRef may have side effects,
							// unless the base is reading from 'this'
							// in a non-static method		
							isEssential = (isStatic || thisLocal != ifr.getBase());			
						} 
					}
					else if (rhs instanceof DivExpr || rhs instanceof RemExpr) {
						BinopExpr expr = (BinopExpr) rhs;

						Type t1 = expr.getOp1().getType();
						Type t2 = expr.getOp2().getType();

						// Can trigger a division by zero
						isEssential  = IntType.v().equals(t1) || LongType.v().equals(t1)
						            || IntType.v().equals(t2) || LongType.v().equals(t2);	
						
						if (isEssential && IntType.v().equals(t2)) {
							Value v = expr.getOp2();
							if (v instanceof IntConstant) {
								IntConstant i = (IntConstant) v;
								isEssential = (i.value == 0);
							}
						}
						if (isEssential && LongType.v().equals(t2)) {
							Value v = expr.getOp2();
							if (v instanceof LongConstant) {
								LongConstant l = (LongConstant) v;
								isEssential = (l.value == 0);
							}
						}
					}
				}
			}
			
			if (isEssential) {
				q.addFirst(s);
			}
			
			allEssential &= isEssential;
		}
				
		if ( checkInvoke || !allEssential ) {		
			// Add all the statements which are used to compute values
			// for the essential statements, recursively 
			
	        final LocalDefs localDefs = LocalDefs.Factory.newLocalDefs(b);	        
			
			if ( !allEssential ) {		
				Set<Unit> essential = new HashSet<Unit>(b.getUnits().size());
				while (!q.isEmpty()) {
					Unit s = q.removeFirst();			
					if ( essential.add(s) ) {
						for (ValueBox box : s.getUseBoxes()) {
							Value v = box.getValue();
							if (v instanceof Local) {
								Local l = (Local) v;
								List<Unit> defs = localDefs.getDefsOfAt(l, s);
								if (defs != null)
									q.addAll(defs);
							}
						}
					}
				}
				// Remove the dead statements
				units.retainAll(essential);		
			}
		}
		if (Options.v().time()) {
			Timers.v().deadCodeTimer.end();
		}
	}
}
