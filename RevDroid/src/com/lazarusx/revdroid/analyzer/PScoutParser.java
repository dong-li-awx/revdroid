package com.lazarusx.revdroid.analyzer;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;

public class PScoutParser {
	private String filePath;

	public static PScoutParser fromFile(String filePath) throws IOException {
		PScoutParser parser = new PScoutParser();
		parser.filePath = filePath;
		return parser;
	}

	private PScoutParser() {

	}

	public ArrayList<AndroidMethod> parse(Set<String> permissions)
			throws IOException {
		ArrayList<AndroidMethod> methodsConcerned = new ArrayList<AndroidMethod>();
		BufferedReader reader = new BufferedReader(
				new FileReader(this.filePath));

		String line;
		while ((line = reader.readLine()) != null) {
			if (line.startsWith("Permission:")) {
				String permission = line.substring(11);

				if (permissions.contains(permission)) {
					reader.readLine();

					while ((line = reader.readLine()) != null
							&& line.startsWith("<")) {
						String[] tokens = line.split(" ");

						String className = tokens[0].substring(1,
								tokens[0].length() - 1);
						String returnType = tokens[1];
						String methodBody = tokens[2];
						String methodName = methodBody.substring(0,
								methodBody.indexOf('('));
						String[] parameters = methodBody.substring(
								methodBody.indexOf('(') + 1,
								methodBody.indexOf(')')).split(",");

						AndroidMethod method = new AndroidMethod(methodName,
								Arrays.asList(parameters), returnType,
								className);
												
						if (methodsConcerned.contains(method)) {
							method = methodsConcerned.get(methodsConcerned.indexOf(method));
							method.addPermission(permission);
						} else {
							method.addPermission(permission);
							methodsConcerned.add(method);
						}
					}
				}
			}
		}

		if (reader != null) {
			reader.close();
		}

		return methodsConcerned;
	}
}
