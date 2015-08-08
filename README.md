# AONT-Tolstoy
Crypto for the masses
Here’s another submission to everyone, no restrictions imposed. This one is rather more complete, providing GUI interface, as well as precompiled standalone versions for Mac and Windows.

AONT-Tolstoy:  1-click encode / decode of confidential information — no keys needed

First up AONT = All Or Nothing Transforms = a secure way to transmit a document to a recipient in such a way that the recipient either gets the entire unmolested document in originally submitted form, or nothing at all. This idea goes back to Ronald Rivest of MIT. Very clever idea. It is crypto without being crypto in a legal sense.

The tool does the following to text typed into the message pane, or a drag & drop collection of files, or a collection of files from the Files menu:

1. Compress the text using Lempel-Ziv self-describing lossless compression to squeeze out the waste and heighten innate entropy

2. Encrypt the compressed data with AES-256 and a randomly chosen key. You don’t know what that key is, and you don’t need to know.

3. Compute the SHA-256 of the crypto text and append the XOR of that hash with the random key to the crypto text.

Now we have extremely high entropy and it stands out like a sore thumb. To stop drawing attention to yourself, the tool next does

4. Form the Huffman encoding of english text from Tolstoy’s “War and Peace” using a 3-level Hidden Markov Model to make the resulting plain text look like real sentences. The content is pure gibberish, but you have to look closely to see that. This is a better approach than just choosing random words.

The text is confidentially encoded, not airtight encryption, but it avoids sniffers looking for high-entropy crypto text, and you have to take the whole message or you get nothing. Furthermore, you can’t reveal anything under duress about the key because you truly don’t know what it is. (Warning… that may not save your neck!) But in front of a judge you can truthfully state that you don’t know the decryption key.

However, if you successfully extract the right English content, and shove it through the tool, the decryption key is there at the end of the crypto text, provided you haven’t damaged the crypto text in any manner. And it will decrypt for you.

All characters, punctuation, character case is significant, but arbitrary whitespace can be inserted between the words.

Example:

“This is a test!” —>

---------- SNIP HERE --------------
Mary?" but said he, taking this way!" who had brought for others, attain the 
laws the Russian nest gave to Moscow, though he spoke with you! one of his 
thighbone into deep dissatisfaction of Borodino. open-mouthed of musketry 
removed army, the Russian army- packages tone handkerchiefs broke son such 
purification. reports true more wars. examples, made with clear Prince Andrew. 
On day that they have outraged Europe. the old man with bare were eager 
sufferings, amusement asked a commissariat to kiss his conduct infinite, 
---------- SNIP HERE --------------

Each time you run this it will generate totally different apparently random output.

What we are doing here is akin to spectral shaping, but applied to the histogram of the plaintext message. We first whiten the message = maximum entropy encoding, then impress the histogram of “War and Peace” on that white histogram to produce the colored histogram that appears to be English prose. High entropy encoding implies compression. The impressing of English prose statistics implies re-inflation.

- DM

