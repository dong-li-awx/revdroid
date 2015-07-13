package com.lazarusx.revdroid.analyzer;

import soot.jimple.Stmt;

public class Misusage {
	private Stmt stmt;
	private AndroidMethod method;

	public Misusage(Stmt stmt, AndroidMethod method) {
		this.stmt = stmt;
		this.method = method;
	}

	public Stmt getStmt() {
		return stmt;
	}

	public AndroidMethod getMethod() {
		return method;
	}
}
