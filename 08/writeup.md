<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>welcome</title>
  <link rel="stylesheet" href="https://stackedit.io/style.css" />
</head>

<body class="stackedit">
  <div class="stackedit__html"><h3 id="introduction">Introduction</h3>
<p>The problem I considered for this exercise was kingdom: a crafted non-stripped binary designed to test symbolic execution engines. The binary contains a series of “walls” that must be solved sequentially. To the best of my knowledge, no tool has been able to automatically solve the challenges starting with only the binary code. I used a combination of automation and static analysis to work through each wall.</p>
<h3 id="survey">Survey</h3>
<p>The first thing I did when auditing kingdom was to look at the decompilation. <em>Figure 1</em> shows the natural auditing start point, <code>main</code>.</p>
<pre class=" language-c"><code class="prism  language-c"><span class="token keyword">int</span> <span class="token function">main</span><span class="token punctuation">(</span><span class="token keyword">int</span> argc<span class="token punctuation">,</span><span class="token keyword">char</span> <span class="token operator">*</span><span class="token operator">*</span>argv<span class="token punctuation">)</span><span class="token punctuation">{</span>
  <span class="token keyword">char</span> cVar1<span class="token punctuation">;</span>
  uint8_t uVar2<span class="token punctuation">;</span>
  <span class="token keyword">int</span> iVar3<span class="token punctuation">;</span>
  ulong uVar4<span class="token punctuation">;</span>
  
  <span class="token keyword">if</span> <span class="token punctuation">(</span>argc <span class="token operator">==</span> <span class="token number">0xc</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
    <span class="token function">fprintf</span><span class="token punctuation">(</span><span class="token constant">stderr</span><span class="token punctuation">,</span><span class="token string">"Run Program Correctly Wall destroyed...please continue (%u/%u)\n"</span><span class="token punctuation">,</span><span class="token number">0</span><span class="token punctuation">,</span><span class="token number">10</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
    uVar2 <span class="token operator">=</span> <span class="token function">gcd_test</span><span class="token punctuation">(</span>argv<span class="token punctuation">[</span><span class="token number">1</span><span class="token punctuation">]</span><span class="token punctuation">,</span>argv<span class="token punctuation">[</span><span class="token number">2</span><span class="token punctuation">]</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
    <span class="token keyword">if</span> <span class="token punctuation">(</span>uVar2 <span class="token operator">==</span> <span class="token number">3</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
      <span class="token function">fprintf</span><span class="token punctuation">(</span><span class="token constant">stderr</span><span class="token punctuation">,</span><span class="token string">"GCD Wall destroyed - 2 achievments awarded...please continue (%u/%u)\n"</span><span class="token punctuation">,</span><span class="token number">2</span><span class="token punctuation">,</span><span class="token number">10</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
      uVar2 <span class="token operator">=</span> <span class="token function">malicious_aes_test</span><span class="token punctuation">(</span>argv<span class="token punctuation">[</span><span class="token number">3</span><span class="token punctuation">]</span><span class="token punctuation">)</span><span class="token punctuation">;</span>
      <span class="token keyword">if</span> <span class="token punctuation">(</span>uVar2 <span class="token operator">==</span> <span class="token number">3</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
        <span class="token function">fprintf</span><span class="token punctuation">(</span><span class="token constant">stderr</span><span class="token punctuation">,</span>
                <span class="token string">"Malicious AES Wall destroyed - achievment awarded...please continue (%u/%u)\n"</span><span class="token punctuation">,</span><span class="token number">3</span><span class="token punctuation">,</span><span class="token number">10</span>
               <span class="token punctuation">)</span><span class="token punctuation">;</span>
<span class="token punctuation">.</span><span class="token punctuation">.</span><span class="token punctuation">.</span>
</code></pre>
<p><em>Figure 1.</em> The main function of kingdom.</p>
<p>Immediately apparent in <code>main</code> is the requirement that <code>argv</code> must have <code>0xc</code> many elements: <code>argc==0xc</code>. Running the program as in <em>Figure 2</em> causes us to get past this check.</p>
<pre><code>% ./kingdom `python -c "print ' '.join(['a']*0xb)"`
Run Program Correctly Wall destroyed...please continue (0/10)
</code></pre>
<p><em>Figure 2.</em> Passing achievements <code>0</code> of <code>10</code>.</p>
<h3 id="gcd">GCD</h3>
<p>For this wall, I had to reason about the function symbol <code>gcd_test</code>. This function takes two arguments and converts them to integers. It asserts that neither are equal to <code>0x3a</code> and that the second is not equal to <code>0</code>.  Then <code>gcd_test</code> calls a new symbol, <code>gcd</code> on the converted arguments. If the return value of <code>gcd</code> is <code>0x3a</code>, we print the string “<em>GCD Wall destroyed …</em>” from <em>Figure 1</em>.</p>
<pre class=" language-c"><code class="prism  language-c">uint8_t <span class="token function">gcd</span><span class="token punctuation">(</span>uint8_t a<span class="token punctuation">,</span>uint8_t b<span class="token punctuation">)</span><span class="token punctuation">{</span>
  <span class="token keyword">if</span> <span class="token punctuation">(</span>b <span class="token operator">!=</span> <span class="token number">0</span><span class="token punctuation">)</span> <span class="token punctuation">{</span>
    a <span class="token operator">=</span> <span class="token function">gcd</span><span class="token punctuation">(</span>b<span class="token punctuation">,</span>a <span class="token operator">%</span> b<span class="token punctuation">)</span><span class="token punctuation">;</span>
  <span class="token punctuation">}</span>
  <span class="token keyword">return</span> a<span class="token punctuation">;</span>
<span class="token punctuation">}</span>
</code></pre>
<p><em>Figure 3.</em> The function symbol <code>gcd</code>.</p>
<p>While I’m sure it should be fairly easy to come up with two numbers who share a <code>gcd</code> of <code>0x3a</code>, it was also quite easy to just have <code>angr</code> figure out this function for me.</p>
<pre class=" language-python"><code class="prism  language-python"><span class="token keyword">def</span> <span class="token function">wall1</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">:</span>
  <span class="token comment">#setup the arguments</span>
  arg1<span class="token punctuation">,</span> arg2 <span class="token operator">=</span> <span class="token punctuation">[</span>claripy<span class="token punctuation">.</span>BVS<span class="token punctuation">(</span><span class="token string">"arg{}"</span><span class="token punctuation">.</span><span class="token builtin">format</span><span class="token punctuation">(</span>i<span class="token punctuation">)</span><span class="token punctuation">,</span> <span class="token number">8</span><span class="token punctuation">)</span> <span class="token keyword">for</span> i <span class="token keyword">in</span> <span class="token punctuation">(</span><span class="token number">1</span><span class="token punctuation">,</span><span class="token number">2</span><span class="token punctuation">)</span><span class="token punctuation">]</span>
  s <span class="token operator">=</span> p<span class="token punctuation">.</span>factory<span class="token punctuation">.</span>blank_state<span class="token punctuation">(</span><span class="token punctuation">)</span>
  <span class="token comment">#program asserts the args cannot be a trivial solution</span>
  s<span class="token punctuation">.</span>add_constraints<span class="token punctuation">(</span>arg1<span class="token operator">!=</span><span class="token number">0x3a</span><span class="token punctuation">,</span> arg2<span class="token operator">!=</span><span class="token number">0x3a</span><span class="token punctuation">)</span>
  <span class="token comment">#lookup gcd address</span>
  gcd_addr <span class="token operator">=</span> p<span class="token punctuation">.</span>loader<span class="token punctuation">.</span>find_symbol<span class="token punctuation">(</span><span class="token string">'gcd'</span><span class="token punctuation">)</span><span class="token punctuation">.</span>rebased_addr
  gcd <span class="token operator">=</span> p<span class="token punctuation">.</span>factory<span class="token punctuation">.</span><span class="token builtin">callable</span><span class="token punctuation">(</span>gcd_addr<span class="token punctuation">,</span> base_state<span class="token operator">=</span>s<span class="token punctuation">)</span>
  logger<span class="token punctuation">.</span>info<span class="token punctuation">(</span><span class="token string">"starting symbolic execution: gcd(%s, %s)"</span><span class="token punctuation">,</span>arg1<span class="token punctuation">,</span>arg2<span class="token punctuation">)</span>
  r <span class="token operator">=</span> gcd<span class="token punctuation">(</span>arg1<span class="token punctuation">,</span>arg2<span class="token punctuation">)</span>
  s <span class="token operator">=</span> gcd<span class="token punctuation">.</span>result_state
  s<span class="token punctuation">.</span>add_constraints<span class="token punctuation">(</span>r<span class="token operator">==</span><span class="token number">0x3a</span><span class="token punctuation">)</span>
  logger<span class="token punctuation">.</span>info<span class="token punctuation">(</span><span class="token string">"evaluating arguments"</span><span class="token punctuation">)</span>
  <span class="token keyword">return</span> <span class="token builtin">map</span><span class="token punctuation">(</span><span class="token builtin">str</span><span class="token punctuation">,</span><span class="token punctuation">(</span>s<span class="token punctuation">.</span>solver<span class="token punctuation">.</span><span class="token builtin">eval</span><span class="token punctuation">(</span>arg1<span class="token punctuation">)</span><span class="token punctuation">,</span> s<span class="token punctuation">.</span>solver<span class="token punctuation">.</span><span class="token builtin">eval</span><span class="token punctuation">(</span>arg2<span class="token punctuation">)</span><span class="token punctuation">)</span>
</code></pre>
<p><em>Figure 4.</em> The <code>angr</code> solution to the gcd wall. After 15.798 cpu seconds, <code>angr</code> returns the results <code>174</code> and <code>116</code>.</p>
<p>In the function shown in <em>Figure 4</em>, I first define two 8-bit symbolic bit vectors called <code>arg1</code> and <code>arg2</code>. Then I create an empty state object from which I will begin symbolic execution. I assert that neither <code>arg1</code> nor <code>arg2</code> can be the trivial solution <code>0x3a</code>. Next, I find the <code>gcd</code> function in the kingdom binary and wrap it in a python callable object. <code>gcd(arg1,arg2)</code> kicks off the symbolic execution of <code>gcd</code>. When the symbolic execution completes, I extract the resulting state. <code>angr</code> builds this state by merging all returning paths through the program. Next, I assert that the return value of my <code>gcd</code> call must be <code>0x3a</code>. The last step is to ask the SMT solver – <code>z3</code> in this case – to find a satisfying <code>arg1</code> and <code>arg2</code> to the constraints defined in the symbolic state.</p>
<p>I was happy to see that <code>angr</code> could reason about this <code>gcd</code> function as a successful symbolic execution required <code>angr</code> to do frequent state merging and reason about symbolic termination. The reason I began symbolic execution at <code>gcd</code> instead of <code>gcd_test</code>, however, is because <code>angr</code> is not as good at reasoning about things like <code>atoi</code> and <code>strlen</code>. Both of these functions are used in <code>gcd_test</code> to convert the string arguments into integers for <code>gcd</code>. With these <code>SimProcedures</code> – as <code>angr</code> calls them – a common strategy is to evaluate the input arguments into concrete values, run the procedure, then continue simulating from the concrete state. This is not ideal for our analysis and given the choice between writing a fully symbolic <code>SimProcedure</code> or working backwards through <code>atoi</code>, I chose the latter.</p>
<pre><code>% ./kingdom 174 116 `python -c "print ' '.join(['a']*(0xb-2))"`
Run Program Correctly Wall destroyed...please continue (0/10)
174, 116, 58GCD Wall destroyed - 2 achievments awarded...please continue (2/10)
</code></pre>
<p><em>Figure 5.</em> Passing <code>2</code> achievements of <code>10</code>.</p>
<h3 id="aes-key-expansion">AES Key Expansion</h3>
<p>For this next wall, I attempted to symbolically execute <code>malicious_aes_test</code>, called from <code>main</code> in <em>Figure 1</em>. This function requires the player to reverse a key that has undergone the AES key expansion procedure. I set up a script as in <em>Figure 6</em>.</p>
<pre class=" language-python"><code class="prism  language-python"><span class="token keyword">def</span> <span class="token function">wall2</span><span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">:</span>
  <span class="token comment">#setup the key to expand</span>
  logger<span class="token punctuation">.</span>info<span class="token punctuation">(</span><span class="token string">"setting up sym args"</span><span class="token punctuation">)</span>
  key <span class="token operator">=</span> claripy<span class="token punctuation">.</span>BVS<span class="token punctuation">(</span><span class="token string">'key'</span><span class="token punctuation">,</span> <span class="token number">8</span><span class="token operator">*</span><span class="token number">16</span><span class="token punctuation">)</span>
  keyarr <span class="token operator">=</span> <span class="token punctuation">[</span>key<span class="token punctuation">.</span>get_byte<span class="token punctuation">(</span>i<span class="token punctuation">)</span> <span class="token keyword">for</span> i <span class="token keyword">in</span> <span class="token builtin">range</span><span class="token punctuation">(</span><span class="token number">16</span><span class="token punctuation">)</span><span class="token punctuation">]</span>
  <span class="token comment">#Make sure angr only uses 1 solver</span>
  s <span class="token operator">=</span> p<span class="token punctuation">.</span>factory<span class="token punctuation">.</span>blank_state<span class="token punctuation">(</span>remove_options<span class="token operator">=</span><span class="token punctuation">{</span>angr<span class="token punctuation">.</span>options<span class="token punctuation">.</span>COMPOSITE_SOLVER<span class="token punctuation">}</span><span class="token punctuation">)</span>
  s<span class="token punctuation">.</span>add_constraints<span class="token punctuation">(</span><span class="token operator">*</span><span class="token punctuation">[</span>k<span class="token operator">!=</span><span class="token string">'\0'</span> <span class="token keyword">for</span> k <span class="token keyword">in</span> keyarr<span class="token punctuation">]</span><span class="token punctuation">)</span>

  logger<span class="token punctuation">.</span>info<span class="token punctuation">(</span><span class="token string">"starting symbolic execution on aes"</span><span class="token punctuation">)</span> 
  aes_addr <span class="token operator">=</span> p<span class="token punctuation">.</span>loader<span class="token punctuation">.</span>find_symbol<span class="token punctuation">(</span><span class="token string">'malicious_aes_test'</span><span class="token punctuation">)</span><span class="token punctuation">.</span>rebased_addr
  aes <span class="token operator">=</span> p<span class="token punctuation">.</span>factory<span class="token punctuation">.</span><span class="token builtin">callable</span><span class="token punctuation">(</span>aes_addr<span class="token punctuation">,</span> base_state<span class="token operator">=</span>s<span class="token punctuation">)</span>
  <span class="token comment">#when calling the function, use the python list so angr makes a pointer</span>
  r <span class="token operator">=</span> aes<span class="token punctuation">(</span>keyarr<span class="token punctuation">)</span>
  s <span class="token operator">=</span> aes<span class="token punctuation">.</span>result_state
  s<span class="token punctuation">.</span>add_constraints<span class="token punctuation">(</span>r<span class="token operator">==</span><span class="token number">3</span><span class="token punctuation">)</span>
  
  <span class="token comment"># CONTINUED IN FIGURE 10.</span>
</code></pre>
<p><em>Figure 6</em>. Attempting to solve the <em>Malicious AES Wall</em>.</p>
<p>Unfortunately, this code did not pass the “Coffee Test”. The “Coffee Test” describes when you begin a symbolic execution or SAT query, get up from the computer to get a cup of coffee and return to see whether your query has completed or not. If it has not completed, it is unlikely to complete in a reasonable amount of time.</p>
<p>To discover the issue, I enabled <code>DEBUG</code> logging on <code>angr</code>. I found that the symbolic execution would spend an extraordinary time in the solver after the block ending at address <code>0x00403855</code>. This block does quite a few things, but intuition (and a bit of nudging from my adviser) told me the issue would be symbolic look-ups into the AES substitution-box. This table has the symbol <code>Te4</code> in this binary. The problem instruction is replicated in <em>Figure 7</em>. Four instructions in the problem block take the same form.</p>
<pre><code>0040378c 8b 04 85        MOV        EAX,[Te4 + RAX*0x4]
         a0 90 60 00
</code></pre>
<p><em>Figure 7</em>. The symbolic addressing in <code>malicious_aes_test</code>.</p>
<p>So I needed a better way to do the symbolic execution for this instruction. Fortunately, <code>angr</code> allows me to overwrite any arbitrary part of the execution with my own python code. I had to sleep on the problem for a day to come up with how I could be more efficient than <code>angr</code>, though. The solution I thought of was to compare <code>angr</code>'s symbolic addressing to another symbolic execution engine named <code>cryptol</code>. I chose this platform because someone had already programmed the AES key expand algorithm in their domain specific language. <code>cryptol</code> was easily able to reverse the key expansion and did so in a matter of seconds. <em>Figure 8</em> demonstrates this experiment.</p>
<pre class=" language-cryptol"><code class="prism  language-cryptol">AES&gt; :sat \key -&gt; join (join (transpose (ExpandKey key).2)) == 0x048a97a0ac9a53b7d37fd65b15cf1362
  0x414348494556454d454e544157415244 = True
(Total Elapsed Time: 9.497s, using Z3)
</code></pre>
<p><em>Figure 8</em>. Reversing AES key expansion. The solver returned in 9.497 cpu seconds.</p>
<p>By running <code>:s prover=offline</code>, I had <code>cryptol</code> dump the <code>smtlib2</code>. <code>cryptol</code> builds a <code>z3.Function</code> that accepts an 8-bit bit-vector as an argument and returns an 8-bit bit-vector. The benefit to building the sbox table this way is that <code>z3.Function</code>s support symbolic arguments. Apparently, it does this much more efficiently than <code>angr</code>. I should provide one final note on <code>cryptol</code> before I continue. The fact that <code>cryptol</code> can perform this reversal so quickly is not a fair comparison to <code>angr</code> because someone had to write <code>cryptol</code> code for the AES Key Expansion procedure. <code>angr</code> lifts binary code and does analysis on that. This almost always results in a significantly more complicated problem than hand-written formal verification code. In order to solve this AES wall with <code>cryptol</code>, I would have to re-write the entire AES Key Expansion procedure. For <code>angr</code>, on the other hand, I only need to overwrite the <code>MOV</code> in <em>Figure 7</em>.</p>
<pre class=" language-python"><code class="prism  language-python"><span class="token keyword">def</span> <span class="token function">Te4_lookup</span><span class="token punctuation">(</span>s<span class="token punctuation">)</span><span class="token punctuation">:</span>
  <span class="token comment">#use the global list to save offset/result pairs</span>
  t <span class="token operator">=</span> s<span class="token punctuation">.</span><span class="token builtin">globals</span><span class="token punctuation">.</span>get<span class="token punctuation">(</span><span class="token string">'table_lookups'</span><span class="token punctuation">,</span><span class="token punctuation">[</span><span class="token punctuation">]</span><span class="token punctuation">)</span>
  <span class="token comment">#do some logging</span>
  count <span class="token operator">=</span> <span class="token builtin">len</span><span class="token punctuation">(</span>t<span class="token punctuation">)</span>
  logger<span class="token punctuation">.</span>info<span class="token punctuation">(</span><span class="token string">"Te4 inject at %s:%s."</span><span class="token punctuation">,</span> count<span class="token operator">/</span><span class="token number">4</span><span class="token punctuation">,</span> <span class="token builtin">hex</span><span class="token punctuation">(</span>s<span class="token punctuation">.</span>addr<span class="token punctuation">)</span><span class="token punctuation">[</span><span class="token number">2</span><span class="token punctuation">:</span><span class="token punctuation">]</span><span class="token punctuation">.</span>replace<span class="token punctuation">(</span><span class="token string">'L'</span><span class="token punctuation">,</span><span class="token string">''</span><span class="token punctuation">)</span><span class="token punctuation">)</span>
  <span class="token comment">#only 256 options for the offset (from AL)</span>
  offset <span class="token operator">=</span> s<span class="token punctuation">.</span>regs<span class="token punctuation">.</span>rax<span class="token punctuation">[</span><span class="token number">7</span><span class="token punctuation">:</span><span class="token number">0</span><span class="token punctuation">]</span>
  <span class="token comment">#make a new bv and assert that it equals the collected AST (save space in the list)</span>
  index <span class="token operator">=</span> claripy<span class="token punctuation">.</span>BVS<span class="token punctuation">(</span><span class="token string">"idx{}"</span><span class="token punctuation">.</span><span class="token builtin">format</span><span class="token punctuation">(</span>count<span class="token punctuation">)</span><span class="token punctuation">,</span><span class="token number">8</span><span class="token punctuation">)</span>
  s<span class="token punctuation">.</span>add_constraints<span class="token punctuation">(</span>index<span class="token operator">==</span>offset<span class="token punctuation">)</span>
  <span class="token comment">#make a new result array (just the same byte repeated 4 times)</span>
  result <span class="token operator">=</span> claripy<span class="token punctuation">.</span>BVS<span class="token punctuation">(</span><span class="token string">"res{}"</span><span class="token punctuation">.</span><span class="token builtin">format</span><span class="token punctuation">(</span>count<span class="token punctuation">)</span><span class="token punctuation">,</span><span class="token number">8</span><span class="token punctuation">)</span>
  s<span class="token punctuation">.</span>regs<span class="token punctuation">.</span>rax <span class="token operator">=</span> <span class="token builtin">reduce</span><span class="token punctuation">(</span><span class="token keyword">lambda</span> a<span class="token punctuation">,</span>x<span class="token punctuation">:</span> a<span class="token punctuation">.</span>concat<span class="token punctuation">(</span>x<span class="token punctuation">)</span><span class="token punctuation">,</span> 
            repeat<span class="token punctuation">(</span>result<span class="token punctuation">,</span><span class="token number">3</span><span class="token punctuation">)</span><span class="token punctuation">,</span> 
            result<span class="token punctuation">)</span><span class="token punctuation">.</span>zero_extend<span class="token punctuation">(</span><span class="token number">32</span><span class="token punctuation">)</span>
  <span class="token comment">#save the tuple for later assertions (in a z3.Function)</span>
  t<span class="token punctuation">.</span>append<span class="token punctuation">(</span><span class="token punctuation">(</span>index<span class="token punctuation">,</span>result<span class="token punctuation">)</span><span class="token punctuation">)</span>
  s<span class="token punctuation">.</span><span class="token builtin">globals</span><span class="token punctuation">[</span><span class="token string">'table_lookups'</span><span class="token punctuation">]</span> <span class="token operator">=</span> t

<span class="token comment">#these instructions are a symbolic table read from Te4. they look like:</span>
<span class="token comment"># 0040378c  8b 04 85      MOV  EAX,[Te4 + RAX*0x4]</span>
<span class="token comment">#     a0 90 60 00</span>
p<span class="token punctuation">.</span>hook<span class="token punctuation">(</span><span class="token number">0x0040378c</span><span class="token punctuation">,</span> Te4_lookup<span class="token punctuation">,</span> length<span class="token operator">=</span><span class="token number">7</span><span class="token punctuation">)</span>
p<span class="token punctuation">.</span>hook<span class="token punctuation">(</span><span class="token number">0x004037a5</span><span class="token punctuation">,</span> Te4_lookup<span class="token punctuation">,</span> length<span class="token operator">=</span><span class="token number">7</span><span class="token punctuation">)</span>
p<span class="token punctuation">.</span>hook<span class="token punctuation">(</span><span class="token number">0x004037bb</span><span class="token punctuation">,</span> Te4_lookup<span class="token punctuation">,</span> length<span class="token operator">=</span><span class="token number">7</span><span class="token punctuation">)</span>
p<span class="token punctuation">.</span>hook<span class="token punctuation">(</span><span class="token number">0x004037d1</span><span class="token punctuation">,</span> Te4_lookup<span class="token punctuation">,</span> length<span class="token operator">=</span><span class="token number">7</span><span class="token punctuation">)</span>
</code></pre>
<p><em>Figure 9</em>. Overwriting the symbolic table look-ups.</p>
<p>Because <code>angr</code> does not directly support <code>z3.Function</code>s, I had to do something a little tricky. <em>Figure 9</em> shows that when I get to one of the problem instructions, I create a new, unconstrained, symbolic, 8-bit bit-vector named <code>result</code>. I set <code>rax</code>'s value to <code>result</code> repeated four times. Finally, I save the table <code>index</code> bit-vector and <code>result</code> bit-vector so that I can assert the table values later. Asserting them during symbolic execution causes <code>angr</code> to error because it does not know how to handle a <code>z3.Function</code> during it’s simplification procedures.</p>
<pre class=" language-python"><code class="prism  language-python">  <span class="token comment">#now we are going to use the tuples generated by Te4_lookup</span>
  <span class="token comment"># we will build a z3 function then use a symbolic index</span>
  <span class="token comment"># this is much faster than state.memory.load with a symbolic addr</span>
  z3_table <span class="token operator">=</span> z3<span class="token punctuation">.</span>Function<span class="token punctuation">(</span><span class="token string">"Te4"</span><span class="token punctuation">,</span> z3<span class="token punctuation">.</span>BitVecSort<span class="token punctuation">(</span><span class="token number">8</span><span class="token punctuation">)</span><span class="token punctuation">,</span> z3<span class="token punctuation">.</span>BitVecSort<span class="token punctuation">(</span><span class="token number">8</span><span class="token punctuation">)</span><span class="token punctuation">)</span>
  <span class="token comment">#there is only one solver because we specified no composite solver option</span>
  z3_solver <span class="token operator">=</span> s<span class="token punctuation">.</span>solver<span class="token punctuation">.</span>_solver<span class="token punctuation">.</span>_get_solver<span class="token punctuation">(</span><span class="token punctuation">)</span>
  <span class="token comment">#extract the Te4 table from program memory and turn it into a z3 func</span>
  Te4 <span class="token operator">=</span> p<span class="token punctuation">.</span>loader<span class="token punctuation">.</span>find_symbol<span class="token punctuation">(</span><span class="token string">"Te4"</span><span class="token punctuation">)</span><span class="token punctuation">.</span>rebased_addr
  <span class="token keyword">for</span> i <span class="token keyword">in</span> <span class="token builtin">range</span><span class="token punctuation">(</span><span class="token number">256</span><span class="token punctuation">)</span><span class="token punctuation">:</span>
    z3_solver<span class="token punctuation">.</span>add<span class="token punctuation">(</span>z3_table<span class="token punctuation">(</span>i<span class="token punctuation">)</span><span class="token operator">==</span>s<span class="token punctuation">.</span>mem<span class="token punctuation">[</span>Te4<span class="token operator">+</span>i<span class="token operator">*</span><span class="token number">4</span><span class="token punctuation">]</span><span class="token punctuation">.</span>uint8_t<span class="token punctuation">.</span>concrete<span class="token punctuation">)</span>
  <span class="token comment">#for each tuple saved in Te4_lookup, convert to z3 bv then </span>
  <span class="token comment"># assert that the index and result are related via the z3 function</span>
  <span class="token keyword">for</span> e <span class="token keyword">in</span> s<span class="token punctuation">.</span><span class="token builtin">globals</span><span class="token punctuation">[</span><span class="token string">'table_lookups'</span><span class="token punctuation">]</span><span class="token punctuation">:</span>
    idx<span class="token punctuation">,</span> res <span class="token operator">=</span> <span class="token builtin">map</span><span class="token punctuation">(</span>claripy<span class="token punctuation">.</span>backends<span class="token punctuation">.</span>z3<span class="token punctuation">.</span>convert<span class="token punctuation">,</span> e<span class="token punctuation">)</span>
    z3_solver<span class="token punctuation">.</span>add<span class="token punctuation">(</span>z3_table<span class="token punctuation">(</span>idx<span class="token punctuation">)</span><span class="token operator">==</span>res<span class="token punctuation">)</span>
  <span class="token comment">#ensure the problem is sat</span>
  logger<span class="token punctuation">.</span>info<span class="token punctuation">(</span><span class="token string">"Checking satisfiability"</span><span class="token punctuation">)</span>
  query <span class="token operator">=</span> z3_solver<span class="token punctuation">.</span>check<span class="token punctuation">(</span><span class="token punctuation">)</span>
  logger<span class="token punctuation">.</span>info<span class="token punctuation">(</span>query<span class="token punctuation">)</span>
  <span class="token keyword">assert</span><span class="token punctuation">(</span>query<span class="token operator">==</span>z3<span class="token punctuation">.</span>sat<span class="token punctuation">)</span>
  logger<span class="token punctuation">.</span>info<span class="token punctuation">(</span><span class="token string">"Getting model"</span><span class="token punctuation">)</span>
  m <span class="token operator">=</span> z3_solver<span class="token punctuation">.</span>model<span class="token punctuation">(</span><span class="token punctuation">)</span>
  <span class="token comment">#make our function's input a z3 bv</span>
  z3key <span class="token operator">=</span> claripy<span class="token punctuation">.</span>backends<span class="token punctuation">.</span>z3<span class="token punctuation">.</span>convert<span class="token punctuation">(</span>key<span class="token punctuation">)</span>
  <span class="token keyword">def</span> <span class="token function">long_to_str</span><span class="token punctuation">(</span>l<span class="token punctuation">)</span><span class="token punctuation">:</span>
    <span class="token keyword">return</span> <span class="token builtin">hex</span><span class="token punctuation">(</span>l<span class="token punctuation">)</span><span class="token punctuation">[</span><span class="token number">2</span><span class="token punctuation">:</span><span class="token punctuation">]</span><span class="token punctuation">.</span>replace<span class="token punctuation">(</span><span class="token string">'L'</span><span class="token punctuation">,</span><span class="token string">''</span><span class="token punctuation">)</span><span class="token punctuation">.</span>decode<span class="token punctuation">(</span><span class="token string">'hex'</span><span class="token punctuation">)</span>
  resolved_key <span class="token operator">=</span> long_to_str<span class="token punctuation">(</span>m<span class="token punctuation">[</span>z3key<span class="token punctuation">]</span><span class="token punctuation">.</span>as_long<span class="token punctuation">(</span><span class="token punctuation">)</span><span class="token punctuation">)</span>
  logger<span class="token punctuation">.</span>info<span class="token punctuation">(</span><span class="token string">"KEY: %s"</span><span class="token punctuation">,</span> <span class="token builtin">repr</span><span class="token punctuation">(</span>resolved_key<span class="token punctuation">)</span><span class="token punctuation">)</span>
  <span class="token comment"># KEY: 'ACHIEVEMENTAWARD'</span>
  <span class="token keyword">return</span> <span class="token punctuation">[</span>resolved_key<span class="token punctuation">]</span>
</code></pre>
<p><em>Figure 10</em>.  Additional code for the <code>wall2</code> function defined in <em>Figure 6</em>.</p>
<p>In <em>Figure 10</em> I revisit <code>wall2</code> to assert information about pairs saved during <code>Te4_lookup</code>. First, with the help of some folks at <a href="http://angr.slack.com">angr.slack.com</a>, I extract the <code>z3</code> solver object. Next, I define a <code>z3.Function</code> for all possible 8-bit inputs: our sbox table. Then for each <code>idx</code>, <code>res</code> combination saved during <code>Te4_lookup</code> I assert that <code>table[idx]==res</code>. Again, this works because <code>z3.Function</code>s allow a symbolic argument. Finally, I check if the solver’s clauses are satisfiable and extract my key from the resulting model.</p>
<pre><code>% python solve.py
INFO    | 2018-05-15 13:31:57,302 | solve.py | setting up sym args
INFO    | 2018-05-15 13:31:57,309 | solve.py | starting symbolic execution on aes
INFO    | 2018-05-15 13:32:01,868 | solve.py | Checking satisfiability
INFO    | 2018-05-15 13:32:06,739 | solve.py | sat
INFO    | 2018-05-15 13:32:06,740 | solve.py | Getting model
INFO    | 2018-05-15 13:32:06,740 | solve.py | KEY: 'ACHIEVEMENTAWARD'
% ./kingdom 174 116 ACHIEVEMENTAWARD `python -c "print ' '.join(['a']*(0xb-3))"`
Run Program Correctly Wall destroyed...please continue (0/10)
174, 116, 58GCD Wall destroyed - 2 achievments awarded...please continue (2/10)
Malicious AES Wall destroyed - achievment awarded...please continue (3/10)
Symbolic Termination Wall destroyed - achievment awarded...please continue (4/10)
Control Flow Merging Wall destroyed - 2 achievments awarded...please continue (6/10)
Advanced_Control Flow Merging Wall destroyed - 2 achievments awarded...please continue (8/10)
</code></pre>
<p><em>Figure 11</em>.  <code>angr</code> passes the <em>Malicious AES Wall</em> in 11.712 cpu seconds. This with the additional <em>a</em>’s brings us to <code>8</code> out of <code>10</code> achievements solved.</p>
<h3 id="achievements-4-through-9">Achievements 4 through 9</h3>
<p>As demonstrated in <em>Figure 11</em>, my very simple fuzzing (all <em>a</em>’s) got us through some fairly tricky challenges. I did not test <code>angr</code>'s performance on these due to the significant time investment in the <em>Malicious AES Wall</em>. For the 9th achievement, I looked at the <code>exploitmealso</code> function symbol. To pass achievement <code>9</code> of <code>10</code>, <code>exploitmealso</code> must return <code>B</code>. It is immediately apparent to me that this function copies its arguments into a 1-byte buffer, and the return value is stored above this buffer on the stack. Without much more analysis, I tried passing a few <code>B</code>s and passed the wall.</p>
<pre><code>% ./kingdom 174 116 ACHIEVEMENTAWARD `python -c "print ' '.join(['a']*5+['B'*5]+['a']*2)"`
Run Program Correctly Wall destroyed...please continue (0/10)
174, 116, 58GCD Wall destroyed - 2 achievments awarded...please continue (2/10)
Malicious AES Wall destroyed - achievment awarded...please continue (3/10)
Symbolic Termination Wall destroyed - achievment awarded...please continue (4/10)
Control Flow Merging Wall destroyed - 2 achievments awarded...please continue (6/10)
Advanced_Control Flow Merging Wall destroyed - 2 achievments awarded...please continue (8/10)
Exploit Chaining Wall destroyed - achievment awarded...please continue (9/10)
</code></pre>
<p><em>Figure 12</em>. Passing achievements <code>9</code> of <code>10</code>.</p>
<h3 id="program-synthesis">Program Synthesis</h3>
<h3 id="conclusion">Conclusion</h3>
<p><code>angr</code> made the <em>Malicious AES Wall</em> much easier than manually reversing the math done during key expansion. It solved <em>GCD</em> quickly once I started past the <code>atoi</code> and <code>strlen</code> calls. Overall, the combination of manual analysis and automated analysis was more effective than either alone.</p>
</div>
</body>

</html>
