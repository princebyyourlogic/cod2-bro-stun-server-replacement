// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 codstun contributors
// Ghidra headless script: locate discovery-related strings and their callers.
// @category CODSTUN
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class Discover extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File out = new File(args[0]);
        out.mkdirs();
        TreeMap<String, Function> targets = new TreeMap<>();
        PrintWriter refs = new PrintWriter(new File(out, "references.txt"));
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext() && !monitor.isCancelled()) {
            Data d = data.next();
            if (!d.hasStringValue()) continue;
            String s = String.valueOf(d.getValue());
            if (!(s.contains("bdIPDiscovery") || s.contains("bdNATTypeDiscovery") ||
                  s.contains("bdNATTraversalPacket") || s.contains("bro.stun") ||
                  s.contains("Reply for test") || s.contains("discovery") ||
                  s.contains("NAT Trav") || s.contains("NAT req") || s.contains("NAT Type"))) continue;
            refs.println(d.getAddress() + " " + s);
            ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
            while (ri.hasNext()) {
                Reference r = ri.next();
                Function f = getFunctionContaining(r.getFromAddress());
                refs.println("  " + r.getFromAddress() + " " + (f == null ? "?" : f.getName() + " " + f.getEntryPoint()));
                if (f != null) targets.put(f.getEntryPoint().toString(), f);
            }
        }
        refs.close();
        // Packet serializers/deserializers and the socket address helpers.
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) {
            Function f = fi.next();
            long a = f.getEntryPoint().getOffset();
            if ((a >= 0x3c2cf0 && a <= 0x3c4730) ||
                (a >= 0x3a5800 && a <= 0x3a8400) ||
                (a >= 0x398dfc && a <= 0x399640))
                targets.put(f.getEntryPoint().toString(), f);
        }
        if (args.length > 1) {
            for (int i=1;i<args.length;i++) {
                Function f = getFunctionContaining(toAddr(args[i]));
                if (f != null) targets.put(f.getEntryPoint().toString(),f);
            }
        }
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        PrintWriter code = new PrintWriter(new File(out,"functions.c"));
        for (Function f : targets.values()) {
            code.println("\n// ADDRESS " + f.getEntryPoint() + " " + f.getName());
            DecompileResults res = di.decompileFunction(f, 45, monitor);
            if(res.decompileCompleted()) code.println(res.getDecompiledFunction().getC());
            else code.println("// ERROR " + res.getErrorMessage());
        }
        code.close();
        di.dispose();
        println("CODSTUN exported " + targets.size() + " functions to " + out);
    }
}
