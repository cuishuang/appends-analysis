
## 1. (false positive:todo)   https://go-mod-viewer.appspot.com/9fans.net/go@v0.0.7/cmd/acme/xfid.go#L403


```go
  394  func fullrunewrite(x *Xfid) []rune {
   395  	q := len(x.f.rpart)
   396  	cnt := len(x.fcall.Data)
   397  	if q > 0 {
   398  		x.fcall.Data = x.fcall.Data[:cnt+q]
   399  		copy(x.fcall.Data[q:], x.fcall.Data)
   400  		copy(x.fcall.Data, x.f.rpart[:q])
   401  		x.f.rpart = x.f.rpart[:0]
   402  	}
   403  	r := make([]rune, cnt)
   404  	nb, nr, _ := runes.Convert(x.fcall.Data, r, false)
   405  	r = r[:nr]
   406  	// approach end of buffer
   407  	for utf8.FullRune(x.fcall.Data[nb:cnt]) {
   408  		ch, w := utf8.DecodeRune(x.fcall.Data[nb:])
   409  		nb += w
   410  		if ch != 0 {
   411  			r = append(r, ch)
   412  		}
   413  	}
   414  	if nb < cnt {
   415  		if cap(x.f.rpart) < utf8.UTFMax {
   416  			x.f.rpart = make([]byte, 0, utf8.UTFMax)
   417  		}
   418  		x.f.rpart = append(x.f.rpart, x.fcall.Data[nb:]...)
   419  	}
   420  	return r
   421  }
   ```


`runes.Convert` come from  `"9fans.net/go/cmd/acme/internal/runes"`



   <br>




## 2. (false positive:true)   https://go-mod-viewer.appspot.com/aletheiaware.com/cryptogo@v1.2.2/crypto.go#L476



```go
462  func EncryptAESGCM(key, payload []byte) ([]byte, error) {
   463  	// Create cipher
   464  	c, err := aes.NewCipher(key)
   465  	if err != nil {
   466  		return nil, err
   467  	}
   468  
   469  	// Create galois counter mode
   470  	gcm, err := cipher.NewGCM(c)
   471  	if err != nil {
   472  		return nil, err
   473  	}
   474  
   475  	// Generate nonce
   476  	nonce := make([]byte, gcm.NonceSize())
   477  	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
   478  		return nil, err
   479  	}
   480  
   481  	// Encrypt payload
   482  	encrypted := append(nonce, gcm.Seal(nil, nonce, payload, nil)...)
   483  
   484  	return encrypted, nil
   485  }
   ```


 `io.ReadFull` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it


 <br>
 <br>


 ## 3.(false positive:false)   https://go-mod-viewer.appspot.com/aqwari.net/xml@v0.0.0-20210331023308-d9421b293817/xsd/xsd.go#L255


 ```go
    251  // An <xs:annotation> element may contain zero or more <xs:documentation>
   252  // children.  The xsd package joins the content of these children, separated
   253  // with blank lines.
   254  func (doc *annotation) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
   255  	buf := make([][]byte, 1)
   256  	var (
   257  		tok xml.Token
   258  		err error
   259  	)
   260  
   261  Loop:
   262  	for {
   263  		tok, err = d.Token()
   264  		if err != nil {
   265  			break
   266  		}
   267  
   268  		switch tok := tok.(type) {
   269  		case xml.EndElement:
   270  			break Loop
   271  		case xml.StartElement:
   272  			if (tok.Name != xml.Name{schemaNS, "documentation"}) {
   273  				if err := d.Skip(); err != nil {
   274  					return err
   275  				}
   276  			}
   277  			var frag []byte
   278  			if err := d.DecodeElement(&frag, &tok); err != nil {
   279  				return err
   280  			}
   281  			buf = append(buf, bytes.TrimSpace(frag))
   282  		}
   283  	}
   284  	*doc = annotation(bytes.TrimSpace(bytes.Join(buf, []byte("\n\n"))))
   285  
   286  	if err == io.EOF {
   287  		return nil
   288  	}
   289  	return err
   290  }
   ```


   <br>
   <br>


   ## 4. (false positive:true)   https://go-mod-viewer.appspot.com/bitbucket.org/bogdancnb/go-crawlers/libs@v0.0.0-20211207183704-6979d7deb0ac/utils/strings.go#L54

   ```go
      52  //RemoveUnicodeSpaces removes all runes for which unicode.IsSpace returns true
    53  func RemoveUnicodeSpaces(slice []byte) string {
    54  	out := make([]rune, len(slice))
    55  	out = out[:0]
    56  	runes := []rune(string(slice))
    57  	for _, r := range runes {
    58  		if !unicode.IsSpace(r) {
    59  			out = append(out, r)
    60  		}
    61  	}
    62  	return string(out)
    63  }
    ```


```go
out := make([]rune, len(slice))
out = out[:0]
```
equal to

`out := make([]rune, 0, len(slice))`

The assembly code of the two is completely identical.




Perhaps it is indeed necessary to exclude operations such as `sli[i:j]`



<br>
<br>


## 5. (false positive:true)  https://go-mod-viewer.appspot.com/bitbucket.org/digi-sense/gg-core-x@v0.2.101/gg_auth0/jwt/signing/ecdsa.go#L124


```go
  87  // Implements the Sign method from SigningMethod
    88  // For this signing method, key must be an ecdsa.PrivateKey struct
    89  func (m *SigningMethodECDSA) Sign(signingString string, key interface{}) (string, error) {
    90  	// Get the key
    91  	var ecdsaKey *ecdsa.PrivateKey
    92  	switch k := key.(type) {
    93  	case *ecdsa.PrivateKey:
    94  		ecdsaKey = k
    95  	default:
    96  		return "", commons.ErrInvalidKeyType
    97  	}
    98  
    99  	// Create the hasher
   100  	if !m.Hash.Available() {
   101  		return "", commons.ErrHashUnavailable
   102  	}
   103  
   104  	hasher := m.Hash.New()
   105  	hasher.Write([]byte(signingString))
   106  
   107  	// Sign the string and return r, s
   108  	if r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hasher.Sum(nil)); err == nil {
   109  		curveBits := ecdsaKey.Curve.Params().BitSize
   110  
   111  		if m.CurveBits != curveBits {
   112  			return "", commons.ErrInvalidKey
   113  		}
   114  
   115  		keyBytes := curveBits / 8
   116  		if curveBits%8 > 0 {
   117  			keyBytes += 1
   118  		}
   119  
   120  		// We serialize the outpus (r and s) into big-endian byte arrays and pad
   121  		// them with zeros on the left to make sure the sizes work out. Both arrays
   122  		// must be keyBytes long, and the output must be 2*keyBytes long.
   123  		rBytes := r.Bytes()
   124  		rBytesPadded := make([]byte, keyBytes)
   125  		copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)
   126  
   127  		sBytes := s.Bytes()
   128  		sBytesPadded := make([]byte, keyBytes)
   129  		copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)
   130  
   131  		out := append(rBytesPadded, sBytesPadded...)
   132  
   133  		return commons.EncodeSegment(out), nil
   134  	} else {
   135  		return "", err
   136  	}
   137  }
   ```


   There is a copy operation, which should have been excluded. We need to see why it is still detected



   ## 6. (false positive:true)  https://go-mod-viewer.appspot.com/blockwatch.cc/tzgo@v1.18.4/tezos/crypto.go#L177


   ```go
   165  func encryptPrivateKey(key []byte, fn PassphraseFunc) ([]byte, error) {
   166  	if fn == nil {
   167  		return nil, ErrPassphrase
   168  	}
   169  	passphrase, err := fn()
   170  	if err != nil {
   171  		return nil, err
   172  	}
   173  	if len(passphrase) == 0 {
   174  		return nil, ErrPassphrase
   175  	}
   176  
   177  	salt := make([]byte, 8)
   178  	_, err = rand.Read(salt)
   179  	if err != nil {
   180  		return nil, err
   181  	}
   182  	secretboxKey := pbkdf2.Key(passphrase, salt, encIterations, encKeyLen, sha512.New)
   183  
   184  	var (
   185  		tmp   [32]byte
   186  		nonce [24]byte // implicitly 0x00..
   187  	)
   188  	copy(tmp[:], secretboxKey)
   189  	enc := secretbox.Seal(nil, key, &nonce, &tmp)
   190  	return append(salt, enc...), nil
   191  }

   ```



`rand.Read` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it





## 7. (false positive:true)  https://go-mod-viewer.appspot.com/blockwatch.cc/tzgo@v1.18.4/tezos/crypto.go#L177

```go
    94  func (s *aesKey) EncryptWithOpts(plain []byte, opts *bccrypto.EncOpts) ([]byte, error) {
    95  	iv := make([]byte, s.blockSize)
    96  	if _, err := rand.Read(iv); err != nil {
    97  		return nil, err
    98  	}
    99  	var cipherWithPad []byte
   100  	switch opts.BlockMode {
   101  	case modes.BLOCK_MODE_CBC:
   102  		switch opts.EncodingType {
   103  		case modes.PADDING_PKCS5:
   104  			plainWithPad := util.PKCS5Padding(plain, s.blockSize)
   105  			ciphertex, err := s.p11Ctx.Encrypt(s.keyObject, pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, iv), plainWithPad)
   106  			if err != nil {
   107  				return nil, err
   108  			}
   109  			cipherWithPad = append(iv, ciphertex...)
   110  		default:
   111  			return nil, fmt.Errorf("sm4 CBC encryption fails: invalid padding scheme [%s]", opts.EncodingType)
   112  		}
   113  	default:
   114  		return nil, fmt.Errorf("sm4 encryption fails: unknown cipher block mode [%s]", opts.BlockMode)
   115  	}
   116  
   117  	return cipherWithPad, nil
   118  }
```

The same as `#6`,  `rand.Read` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it



<br>


## 8,9,10,11,12

The same as `#6`,  `rand.Read` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it



## 13. (false positive: false)  https://go-mod-viewer.appspot.com/cisco-app-networking.github.io/networkservicemesh/sdk@v1.0.13/endpoint/routes.go#L50


```go
    48  // NewRoutesEndpoint creates New RoutesEndpoint
    49  func NewRoutesEndpoint(prefixes []string) *RoutesEndpoint {
    50  	routes := make([]*connectioncontext.Route, 1)
    51  	for _, prefix := range prefixes {
    52  		routes = append(routes, &connectioncontext.Route{Prefix: prefix})
    53  	}
    54  	return &RoutesEndpoint{
    55  		routes: routes,
    56  	}
    57  }
```


A very standard case of error




## 14.  (false positive: false)   https://go-mod-viewer.appspot.com/code.cloudfoundry.org/go-metric-registry@v0.0.0-20241016180114-4959be80b5ec/testhelpers/spy_registry.go#L206


```go
   203  func getMetricName(name string, tags map[string]string) string {
   204  	n := name
   205  
   206  	k := make([]string, len(tags))
   207  	for t := range tags {
   208  		k = append(k, t)
   209  	}
   210  	sort.Strings(k)
   211  
   212  	for _, key := range k {
   213  		n += fmt.Sprintf("%s_%s", key, tags[key])
   214  	}
   215  
   216  	return n
   217  }
```

A very standard case of error



<br>
<br>



##  15.  (false positive: true)  https://go-mod-viewer.appspot.com/code.gitea.io/gitea@v1.22.3/modules/util/legacy.go#L56


```go
44  // AESGCMEncrypt (from legacy package): encrypts plaintext with the given key using AES in GCM mode. should be replaced.
    45  func AESGCMEncrypt(key, plaintext []byte) ([]byte, error) {
    46  	block, err := aes.NewCipher(key)
    47  	if err != nil {
    48  		return nil, err
    49  	}
    50  
    51  	gcm, err := cipher.NewGCM(block)
    52  	if err != nil {
    53  		return nil, err
    54  	}
    55  
    56  	nonce := make([]byte, gcm.NonceSize())
    57  	if _, err := rand.Read(nonce); err != nil {
    58  		return nil, err
    59  	}
    60  
    61  	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
    62  	return append(nonce, ciphertext...), nil
    63  }
```

The same as `#6`,  `rand.Read` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it





## 16. (false positive: todo)  https://go-mod-viewer.appspot.com/code.gitea.io/gitea@v1.22.3/routers/web/repo/editor.go#L158


```go
106  func editFile(ctx *context.Context, isNewFile bool) {
   107  	ctx.Data["PageIsViewCode"] = true
   108  	ctx.Data["PageIsEdit"] = true
   109  	ctx.Data["IsNewFile"] = isNewFile
   110  	canCommit := renderCommitRights(ctx)
   111  
   112  	treePath := cleanUploadFileName(ctx.Repo.TreePath)
   113  	if treePath != ctx.Repo.TreePath {
   114  		if isNewFile {
   115  			ctx.Redirect(path.Join(ctx.Repo.RepoLink, "_new", util.PathEscapeSegments(ctx.Repo.BranchName), util.PathEscapeSegments(treePath)))
   116  		} else {
   117  			ctx.Redirect(path.Join(ctx.Repo.RepoLink, "_edit", util.PathEscapeSegments(ctx.Repo.BranchName), util.PathEscapeSegments(treePath)))
   118  		}
   119  		return
   120  	}
   121  
   122  	// Check if the filename (and additional path) is specified in the querystring
   123  	// (filename is a misnomer, but kept for compatibility with GitHub)
   124  	filePath, fileName := path.Split(ctx.Req.URL.Query().Get("filename"))
   125  	filePath = strings.Trim(filePath, "/")
   126  	treeNames, treePaths := getParentTreeFields(path.Join(ctx.Repo.TreePath, filePath))
   127  
   128  	if !isNewFile {
   129  		entry, err := ctx.Repo.Commit.GetTreeEntryByPath(ctx.Repo.TreePath)
   130  		if err != nil {
   131  			HandleGitError(ctx, "Repo.Commit.GetTreeEntryByPath", err)
   132  			return
   133  		}
   134  
   135  		// No way to edit a directory online.
   136  		if entry.IsDir() {
   137  			ctx.NotFound("entry.IsDir", nil)
   138  			return
   139  		}
   140  
   141  		blob := entry.Blob()
   142  		if blob.Size() >= setting.UI.MaxDisplayFileSize {
   143  			ctx.NotFound("blob.Size", err)
   144  			return
   145  		}
   146  
   147  		dataRc, err := blob.DataAsync()
   148  		if err != nil {
   149  			ctx.NotFound("blob.Data", err)
   150  			return
   151  		}
   152  
   153  		defer dataRc.Close()
   154  
   155  		ctx.Data["FileSize"] = blob.Size()
   156  		ctx.Data["FileName"] = blob.Name()
   157  
   158  		buf := make([]byte, 1024)
   159  		n, _ := util.ReadAtMost(dataRc, buf)
   160  		buf = buf[:n]
   161  
   162  		// Only some file types are editable online as text.
   163  		if !typesniffer.DetectContentType(buf).IsRepresentableAsText() {
   164  			ctx.NotFound("typesniffer.IsRepresentableAsText", nil)
   165  			return
   166  		}
   167  
   168  		d, _ := io.ReadAll(dataRc)
   169  
   170  		buf = append(buf, d...)
   171  		if content, err := charset.ToUTF8(buf, charset.ConvertOpts{KeepBOM: true}); err != nil {
   172  			log.Error("ToUTF8: %v", err)
   173  			ctx.Data["FileContent"] = string(buf)
   174  		} else {
   175  			ctx.Data["FileContent"] = content
   176  		}
   177  	} else {
   178  		// Append filename from query, or empty string to allow user name the new file.
   179  		treeNames = append(treeNames, fileName)
   180  	}
   181  
   182  	ctx.Data["TreeNames"] = treeNames
   183  	ctx.Data["TreePaths"] = treePaths
   184  	ctx.Data["BranchLink"] = ctx.Repo.RepoLink + "/src/" + ctx.Repo.BranchNameSubURL()
   185  	ctx.Data["commit_summary"] = ""
   186  	ctx.Data["commit_message"] = ""
   187  	if canCommit {
   188  		ctx.Data["commit_choice"] = frmCommitChoiceDirect
   189  	} else {
   190  		ctx.Data["commit_choice"] = frmCommitChoiceNewBranch
   191  	}
   192  	ctx.Data["new_branch_name"] = GetUniquePatchBranchName(ctx)
   193  	ctx.Data["last_commit"] = ctx.Repo.CommitID
   194  	ctx.Data["PreviewableExtensions"] = strings.Join(markup.PreviewableExtensions(), ",")
   195  	ctx.Data["LineWrapExtensions"] = strings.Join(setting.Repository.Editor.LineWrapExtensions, ",")
   196  	ctx.Data["EditorconfigJson"] = GetEditorConfig(ctx, treePath)
   197  
   198  	ctx.Data["IsEditingFileOnly"] = ctx.FormString("return_uri") != ""
   199  	ctx.Data["ReturnURI"] = ctx.FormString("return_uri")
   200  
   201  	ctx.HTML(http.StatusOK, tplEditFile)
   202  }
   ```


`util.ReadAtMost` is a user-defined functions



<br>
<br>


## 17. (false positive: false) https://go-mod-viewer.appspot.com/dev.azure.com/aidainnovazione0090/DeviceManager/_git/go-mod-core-contracts@v1.0.2/dtos/application.go#L58


```go
    43  // ToApplicationModel transforms the Application DTO to the Application Model
    44  func ToApplicationModel(dto Application) models.Application {
    45  	var d models.Application
    46  	d.Id = dto.Id
    47  	d.Name = dto.Name
    48  	d.OrganizationId = dto.OrganizationId
    49  	d.Latitude = dto.Latitude
    50  	d.Longitude = dto.Longitude
    51  
    52  	devices := make([]models.Device, len(dto.Devices))
    53  	for i, device := range dto.Devices {
    54  		devices[i] = ToDeviceModel(device)
    55  	}
    56  	d.Devices = devices
    57  
    58  	layers := make([]models.Layer, len(dto.Layer))
    59  	for _, l := range dto.Layer {
    60  		layer := models.Layer{
    61  			Id:     l.Id,
    62  			Name:   l.Name,
    63  			Folder: l.Folder,
    64  		}
    65  		layers = append(layers, layer)
    66  	}
    67  
    68  	d.Layer = layers
    69  
    70  	return d
    71  }
```

A very standard case of error


<br>
<br>



## 18. (false positive: true) https://go-mod-viewer.appspot.com/devt.de/krotik/common@v1.5.1/datautil/userdb.go#L119


```go
 104  /*
   105  AddUserEntry adds a new user entry.
   106  */
   107  func (ud *UserDB) AddUserEntry(name, password string, data map[string]interface{}) error {
   108  	var err error
   109  
   110  	ud.DataLock.Lock()
   111  	defer ud.DataLock.Unlock()
   112  
   113  	if _, ok := ud.Data[name]; ok {
   114  		return fmt.Errorf("User %v already exists", name)
   115  	}
   116  
   117  	// Generate a salt for the user
   118  
   119  	salt := make([]byte, sha256.Size)
   120  
   121  	if _, err = io.ReadFull(rand.Reader, salt); err == nil {
   122  
   123  		// Hash the password
   124  
   125  		passhash := sha256.Sum256(append(salt, []byte(password)...))
   126  
   127  		ud.Data[name] = &userDBEntry{
   128  			Passhash:        string((&passhash)[:]),
   129  			Salt:            salt,
   130  			PasshashHistory: []string{},
   131  			Data:            data,
   132  		}
   133  
   134  		err = ud.flush()
   135  	}
   136  
   137  	return err
   138  }
   ```


`rand.Reader` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it



<br>



## 19. (false positive: true) https://go-mod-viewer.appspot.com/devt.de/krotik/common@v1.5.1/datautil/userdb.go#L179


The same as `#18`




## 20. (false positive: false)  https://go-mod-viewer.appspot.com/dubbo.apache.org/dubbo-go/v3@v3.1.1/protocol/dubbo3/dubbo3_protocol.go#L150

```go
   147  // Destroy destroy dubbo3 service.
   148  func (dp *DubboProtocol) Destroy() {
   149  	dp.BaseProtocol.Destroy()
   150  	keyList := make([]string, 16)
   151  
   152  	dp.serverLock.Lock()
   153  	defer dp.serverLock.Unlock()
   154  	// Stop all server
   155  	for k, _ := range dp.serverMap {
   156  		keyList = append(keyList, k)
   157  	}
   158  	for _, v := range keyList {
   159  		if server := dp.serverMap[v]; server != nil {
   160  			server.Stop()
   161  		}
   162  		delete(dp.serverMap, v)
   163  	}
   164  }
```

A very standard case of error




## 21. (false positive: false) https://go-mod-viewer.appspot.com/dubbo.apache.org/dubbo-go/v3@v3.1.1/proxy/proxy_factory/pass_through.go#L104


```go
81  // Invoke is used to call service method by invocation
    82  func (pi *PassThroughProxyInvoker) Invoke(ctx context.Context, invocation protocol.Invocation) protocol.Result {
    83  	result := &protocol.RPCResult{}
    84  	result.SetAttachments(invocation.Attachments())
    85  	url := getProviderURL(pi.GetURL())
    86  
    87  	arguments := invocation.Arguments()
    88  	srv := common.ServiceMap.GetServiceByServiceKey(url.Protocol, url.ServiceKey())
    89  
    90  	var args [][]byte
    91  	if len(arguments) > 0 {
    92  		args = make([][]byte, 0, len(arguments))
    93  		for _, arg := range arguments {
    94  			if v, ok := arg.([]byte); ok {
    95  				args = append(args, v)
    96  			} else {
    97  				result.Err = perrors.New("the param type is not []byte")
    98  				return result
    99  			}
   100  		}
   101  	}
   102  	method := srv.Method()["Service"]
   103  
   104  	in := make([]reflect.Value, 5)
   105  	in = append(in, srv.Rcvr())
   106  	in = append(in, reflect.ValueOf(invocation.MethodName()))
   107  	in = append(in, reflect.ValueOf(invocation.GetAttachmentInterface(constant.ParamsTypeKey)))
   108  	in = append(in, reflect.ValueOf(args))
   109  	in = append(in, reflect.ValueOf(invocation.Attachments()))
   110  
   111  	var replyv reflect.Value
   112  	var retErr interface{}
   113  
   114  	returnValues, callErr := callLocalMethod(method.Method(), in)
   115  
   116  	if callErr != nil {
   117  		logger.Errorf("Invoke function error: %+v, service: %#v", callErr, url)
   118  		result.SetError(callErr)
   119  		return result
   120  	}
   121  
   122  	replyv = returnValues[0]
   123  	retErr = returnValues[1].Interface()
   124  
   125  	if retErr != nil {
   126  		result.SetError(retErr.(error))
   127  		return result
   128  	}
   129  	if replyv.IsValid() && (replyv.Kind() != reflect.Ptr || replyv.Kind() == reflect.Ptr && replyv.Elem().IsValid()) {
   130  		result.SetResult(replyv.Interface())
   131  	}
   132  
   133  	return result
   134  }
```

A very standard case of error



<br>
<br>


## 22. 23. 24. 25. 26 (false positive: false) 




https://go-mod-viewer.appspot.com/dubbo.apache.org/dubbo-go/v3@v3.1.1/registry/servicediscovery/service_instances_changed_listener_impl.go#L117

https://go-mod-viewer.appspot.com/dubbo.apache.org/dubbo-go/v3@v3.1.1/xds/client/resource/filter_chain.go#L113


https://go-mod-viewer.appspot.com/e.coding.net/nimrc/micro/cli@v1.0.0/errors.go#L44


https://go-mod-viewer.appspot.com/flamingo.me/flamingo-commerce/v3@v3.11.0/order/domain/orderDecorator.go#L211


https://go-mod-viewer.appspot.com/gfx.cafe/open/arango@v0.1.0/arango.go#L93

24:
```go
    42  // Errors returns a copy of the errors slice
    43  func (m *multiError) Errors() []error {
    44  	errs := make([]error, len(*m))
    45  	for _, err := range *m {
    46  		errs = append(errs, err)
    47  	}
    48  	return errs
    49  }
```


25:
```go
   207  // GetSourceIds collects the source ids of the items of the group
   208  func (i *GroupedDecoratedOrderItems) GetSourceIds() []string {
   209  	// the group has at least one group in there
   210  	sourceIds := make(map[string]bool, 1)
   211  	result := make([]string, 1)
   212  	for _, item := range i.DecoratedItems {
   213  		sourceID := item.Item.SourceID
   214  		if _, ok := sourceIds[sourceID]; ok {
   215  			continue
   216  		}
   217  
   218  		sourceIds[sourceID] = true
   219  		result = append(result, sourceID)
   220  	}
   221  
   222  	return result
   223  }
```


26:

```go
    92  func (c *Collection[T]) AsyncImport(ctx context.Context, xs []T) error {
    93  	ko := make([]*keyedObject, len(xs))
    94  	for _, v := range xs {
    95  		ko = append(ko, &keyedObject{d: v})
    96  	}
    97  	_, err := c.C().ImportDocuments(ctx, ko, &driver.ImportDocumentOptions{
    98  		OnDuplicate: driver.ImportOnDuplicateReplace,
    99  		Overwrite:   false,
   100  		Complete:    false,
   101  	})
   102  	return err
   103  }
```



A very standard case of error





<br>
<br>


## 27. (false positive: true) https://go-mod-viewer.appspot.com/git.frostfs.info/TrueCloudLab/frostfs-sdk-go@v0.0.0-20241022124111-5361f0ecebd3/session/container_test.go#L556


```go
   551  func TestContainer_VerifyDataSignature(t *testing.T) {
   552  	signer := randSigner()
   553  
   554  	var tok session.Container
   555  
   556  	data := make([]byte, 100)
   557  	rand.Read(data)
   558  
   559  	var sig frostfscrypto.Signature
   560  	require.NoError(t, sig.Calculate(frostfsecdsa.SignerRFC6979(signer), data))
   561  
   562  	var sigV2 refs.Signature
   563  	sig.WriteToV2(&sigV2)
   564  
   565  	require.False(t, tok.VerifySessionDataSignature(data, sigV2.GetSign()))
   566  
   567  	tok.SetAuthKey((*frostfsecdsa.PublicKeyRFC6979)(&signer.PublicKey))
   568  	require.True(t, tok.VerifySessionDataSignature(data, sigV2.GetSign()))
   569  	require.False(t, tok.VerifySessionDataSignature(append(data, 1), sigV2.GetSign()))
   570  	require.False(t, tok.VerifySessionDataSignature(data, append(sigV2.GetSign(), 1)))
   571  }

```




`rand.Read` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it




<br>
<br>




## 28 (false positive: false)  https://go-mod-viewer.appspot.com/gitee.com/h79/goutils@v1.22.10/common/integer.go#L29




```go
    28  func WhereInt[T IntegerType](arr []any, where func(a any) (T, bool)) []T {
    29  	Int := make([]T, len(arr))
    30  	for i := range arr {
    31  		if ret, ok := where(arr[i]); ok {
    32  			Int = append(Int, ret)
    33  		}
    34  	}
    35  	return Int
    36  }
```



A very standard case of error




## 29. 30. 31 (false positive: true)

https://go-mod-viewer.appspot.com/gitee.com/lh-her-team/common@v1.5.1/crypto/pkcs11/aeskey.go#L84


https://go-mod-viewer.appspot.com/gitee.com/lh-her-team/common@v1.5.1/crypto/pkcs11/sm4key.go#L77

https://go-mod-viewer.appspot.com/gitee.com/lh-her-team/common@v1.5.1/crypto/sdf/sm4key.go#L92




`rand.Read` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it





## 32. 33 .34 (false positive: false) 


https://go-mod-viewer.appspot.com/gitee.com/liujinsuo/tool@v0.0.0-20241011111044-767c1a70c502/func.go#L290

https://go-mod-viewer.appspot.com/gitee.com/liuxuezhan/go-micro-v1.18.0@v1.0.0/network/resolver/dnssrv/dnssrv.go#L20

https://go-mod-viewer.appspot.com/github.com/0chain/gosdk@v1.17.11/mobilesdk/zbox/storage.go#L873

32:
```go
   299  // MapMerge 合并多个map到一个新map
   300  func MapMerge[K comparable, V any](m ...map[K]V) map[K]V {
   301  	rt := map[K]V{}
   302  	for i := 0; i < len(m); i++ {
   303  		for k, v := range m[i] {
   304  			rt[k] = v
   305  		}
   306  	}
   307  	return rt
   308  }
```


33:


```go
    14  // Resolve assumes ID is a domain name e.g micro.mu
    15  func (r *Resolver) Resolve(name string) ([]*resolver.Record, error) {
    16  	_, addrs, err := net.LookupSRV("network", "udp", name)
    17  	if err != nil {
    18  		return nil, err
    19  	}
    20  	records := make([]*resolver.Record, len(addrs))
    21  	for _, addr := range addrs {
    22  		address := addr.Target
    23  		if addr.Port > 0 {
    24  			address = fmt.Sprintf("%s:%d", addr.Target, addr.Port)
    25  		}
    26  		records = append(records, &resolver.Record{
    27  			Address: address,
    28  		})
    29  	}
    30  	return records, nil
    31  }
```


34:

```go
   862  func GetRemoteFileMap(allocationID string) (string, error) {
   863  	a, err := getAllocation(allocationID)
   864  	if err != nil {
   865  		return "", err
   866  	}
   867  
   868  	ref, err := a.GetRemoteFileMap(nil, "/")
   869  	if err != nil {
   870  		return "", err
   871  	}
   872  
   873  	fileResps := make([]*fileResp, len(ref))
   874  	for path, data := range ref {
   875  		paths := strings.SplitAfter(path, "/")
   876  		var resp = fileResp{
   877  			Name:     paths[len(paths)-1],
   878  			Path:     path,
   879  			FileInfo: data,
   880  		}
   881  		fileResps = append(fileResps, &resp)
   882  	}
   883  
   884  	retBytes, err := json.Marshal(fileResps)
   885  	if err != nil {
   886  		return "", err
   887  	}
   888  
   889  	return string(retBytes), nil
   890  }

```

A very standard case of error


<br>
<br>





## 35,36  (false positive: true)  



https://go-mod-viewer.appspot.com/github.com/0chain/gosdk@v1.17.11/zboxcore/zboxutil/util.go#L321

https://go-mod-viewer.appspot.com/github.com/0chain/gosdk@v1.17.11/zboxcore/zboxutil/util.go#L330


35:

```go
   314  func ScryptEncrypt(key, text []byte) ([]byte, error) {
   315  	if len(key) == 0 {
   316  		return nil, errors.New("scrypt: key cannot be empty")
   317  	}
   318  	if len(text) == 0 {
   319  		return nil, errors.New("scrypt: plaintext cannot be empty")
   320  	}
   321  	salt := make([]byte, saltSize)
   322  	if _, err := rand.Read(salt); err != nil {
   323  		return nil, err
   324  	}
   325  
   326  	derivedKey, err := scrypt.Key(key, salt, scryptN, scryptR, scryptP, scryptKeyLen)
   327  	if err != nil {
   328  		return nil, err
   329  	}
   330  	nonce := make([]byte, nonceSize)
   331  	if _, err := rand.Read(nonce); err != nil {
   332  		return nil, err
   333  	}
   334  	aead, err := chacha20poly1305.New(derivedKey)
   335  	if err != nil {
   336  		return nil, err
   337  	}
   338  
   339  	ciphertext := aead.Seal(nil, nonce, text, nil)
   340  	ciphertext = append(salt, ciphertext...)
   341  	ciphertext = append(nonce, ciphertext...)
   342  
   343  	return ciphertext, nil
   344  }
```


36:


```go
314  func ScryptEncrypt(key, text []byte) ([]byte, error) {
   315  	if len(key) == 0 {
   316  		return nil, errors.New("scrypt: key cannot be empty")
   317  	}
   318  	if len(text) == 0 {
   319  		return nil, errors.New("scrypt: plaintext cannot be empty")
   320  	}
   321  	salt := make([]byte, saltSize)
   322  	if _, err := rand.Read(salt); err != nil {
   323  		return nil, err
   324  	}
   325  
   326  	derivedKey, err := scrypt.Key(key, salt, scryptN, scryptR, scryptP, scryptKeyLen)
   327  	if err != nil {
   328  		return nil, err
   329  	}
   330  	nonce := make([]byte, nonceSize)
   331  	if _, err := rand.Read(nonce); err != nil {
   332  		return nil, err
   333  	}
   334  	aead, err := chacha20poly1305.New(derivedKey)
   335  	if err != nil {
   336  		return nil, err
   337  	}
   338  
   339  	ciphertext := aead.Seal(nil, nonce, text, nil)
   340  	ciphertext = append(salt, ciphertext...)
   341  	ciphertext = append(nonce, ciphertext...)
   342  
   343  	return ciphertext, nil
   344  }

```



`rand.Read` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it






## 37. (false positive: false)  https://go-mod-viewer.appspot.com/github.com/0xsequence/ethkit@v1.29.1/ethcoder/merkle_proof.go#L145


```go
 143  func (mt *MerkleTree[TLeaf]) GetHexProof(leaf TLeaf) [][]byte {
   144  	proof, _ := mt.GetProof(leaf)
   145  	hexProof := make([][]byte, len(proof))
   146  	for _, p := range proof {
   147  		hexProof = append(hexProof, []byte(p.Data))
   148  	}
   149  	return hexProof
   150  }
```


A very standard case of error





## 38. (false positive: true)  https://go-mod-viewer.appspot.com/github.com/Appkube-awsx/awsx-common@v1.4.2/crypto/crypto.go#L22

```go

    13  func Encrypt(plainText string) (string, error) {
    14  	data := []byte(plainText)
    15  	block, err := aes.NewCipher(config.Key)
    16  	if err != nil {
    17  		return "", err
    18  	}
    19  
    20  	// The IV needs to be unique, but not necessarily secure.
    21  	// In this example, we use a random 16-byte IV for simplicity.
    22  	iv := make([]byte, aes.BlockSize)
    23  	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
    24  		return "", err
    25  	}
    26  
    27  	stream := cipher.NewCFBEncrypter(block, iv)
    28  	ciphertext := make([]byte, len(data))
    29  	stream.XORKeyStream(ciphertext, data)
    30  
    31  	// Prepend the IV to the ciphertext.
    32  	ciphertext = append(iv, ciphertext...)
    33  	encoded := base64.StdEncoding.EncodeToString(ciphertext)
    34  
    35  	return encoded, nil
    36  }
```



`io.ReadFull(rand.Reader, sli)` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it



<br>
<br>

## 39. 40  (false positive: false)



39:

https://go-mod-viewer.appspot.com/github.com/Axway/agent-sdk@v1.1.101/pkg/apic/apiserver/clients/api/v1/fake.go#L423

```go
   421  func attrsAsIdxs(attrs map[string]string) []string {
   422  	// update attributes
   423  	idxs := make([]string, len(attrs))
   424  
   425  	for key, val := range attrs {
   426  		idxs = append(idxs, fmt.Sprintf("%s;%s", key, val))
   427  	}
   428  	return idxs
   429  }
```



40:

https://go-mod-viewer.appspot.com/github.com/BotBotMe/botbot-bot@v0.0.0-20180428050013-f77af5b99e6e/network/irc/irc_test.go#L163

```go
// Test sending messages too fast
   155  func TestFlood(t *testing.T) {
   156  	common.SetGlogFlags()
   157  
   158  	NUM := 5
   159  
   160  	fromServer := make(chan *line.Line)
   161  	receivedCounter := make(chan bool)
   162  	mockSocket := common.MockSocket{Counter: receivedCounter}
   163  	channels := make([]*common.Channel, 1)
   164  	channels = append(channels, &common.Channel{Name: "test", Fingerprint: "uuid-string"})
   165  
   166  	chatbot := &ircBot{
   167  		id:               99,
   168  		address:          "fakehost",
   169  		nick:             "test",
   170  		realname:         "Unit Test",
   171  		password:         "test",
   172  		serverIdentifier: "localhost.test",
   173  		rateLimit:        time.Second,
   174  		fromServer:       fromServer,
   175  		channels:         channels,
   176  		pingResponse:     make(chan struct{}, 10), // HACK: This is to avoid the current deadlock
   177  		sendQueue:        make(chan []byte, 256),
   178  	}
   179  	chatbot.init(&mockSocket)
   180  
   181  	startTime := time.Now()
   182  
   183  	// Send the messages
   184  	for i := 0; i < NUM; i++ {
   185  		chatbot.Send("test", "Msg "+strconv.Itoa(i))
   186  	}
   187  
   188  	// Wait for them to 'arrive' at the socket
   189  	for numGot := 0; numGot <= NUM; numGot++ {
   190  		<-receivedCounter
   191  	}
   192  
   193  	elapsed := int64(time.Since(startTime))
   194  
   195  	expected := int64((NUM-1)/4) * int64(chatbot.rateLimit)
   196  	if elapsed < expected {
   197  		t.Error("Flood prevention did not work")
   198  	}
   199  
   200  }
```

A very standard case of error




<br>

## 41~47  (false positive: false) 


https://go-mod-viewer.appspot.com/github.com/ChainSafe/chainbridge-core@v1.4.2/keystore/keyring.go#L99
https://go-mod-viewer.appspot.com/github.com/ChainSafe/chainbridge-utils@v1.0.6/keystore/keyring.go#L98
https://go-mod-viewer.appspot.com/github.com/CiscoM31/godata@v1.0.10/providers/mysql.go#L205
https://go-mod-viewer.appspot.com/github.com/CiscoM31/godata@v1.0.10/providers/mysql.go#L209
https://go-mod-viewer.appspot.com/github.com/Cloud-Foundations/Dominator@v0.3.4/lib/srpc/server.go#L639


A very standard case of error



## 48  (false positive: todo)   https://go-mod-viewer.appspot.com/github.com/DFWallet/tendermint-cosmos@v0.0.2/crypto/secp256k1/secp256k1_internal_test.go#L15


```go
    13  func Test_genPrivKey(t *testing.T) {
    14  
    15  	empty := make([]byte, 32)
    16  	oneB := big.NewInt(1).Bytes()
    17  	onePadded := make([]byte, 32)
    18  	copy(onePadded[32-len(oneB):32], oneB)
    19  	t.Logf("one padded: %v, len=%v", onePadded, len(onePadded))
    20  
    21  	validOne := append(empty, onePadded...)
    22  	tests := []struct {
    23  		name        string
    24  		notSoRand   []byte
    25  		shouldPanic bool
    26  	}{
    27  		{"empty bytes (panics because 1st 32 bytes are zero and 0 is not a valid field element)", empty, true},
    28  		{"curve order: N", secp256k1.S256().N.Bytes(), true},
    29  		{"valid because 0 < 1 < N", validOne, false},
    30  	}
    31  	for _, tt := range tests {
    32  		tt := tt
    33  		t.Run(tt.name, func(t *testing.T) {
    34  			if tt.shouldPanic {
    35  				require.Panics(t, func() {
    36  					genPrivKey(bytes.NewReader(tt.notSoRand))
    37  				})
    38  				return
    39  			}
    40  			got := genPrivKey(bytes.NewReader(tt.notSoRand))
    41  			fe := new(big.Int).SetBytes(got[:])
    42  			require.True(t, fe.Cmp(secp256k1.S256().N) < 0)
    43  			require.True(t, fe.Sign() > 0)
    44  		})
    45  	}
    46  }
```


`I'm not quite sure. If it is a false alarm, it may be difficult to rule out this situation`


demo:

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	//buf := make([]int, 1024)
	//buf = buf[:10]
	//
	//fmt.Println(buf)

	empty := make([]byte, 32)
	oneB := big.NewInt(1).Bytes()
	onePadded := make([]byte, 32)
	copy(onePadded[32-len(oneB):32], oneB)
	fmt.Printf("one padded: %v, len=%v\n", onePadded, len(onePadded))

	validOne := append(empty, onePadded...)
	fmt.Printf("validOne: %v, len=%v\n", validOne, len(validOne))

}
```


```go
one padded: [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1], len=32
validOne: [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1], len=64
```

if `empty := make([]byte, 32)` --> `empty := make([]byte, 0, 32)`, the output:


```go
one padded: [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1], len=32
validOne: [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1], len=32
```

seem it is a bug.



<br>
<br>


## 49  (false positive: false)   https://go-mod-viewer.appspot.com/github.com/DataDog/agent-payload/v5@v5.0.134/process/connections.go#L50



A very standard case of error



## 50  (false positive: false) https://go-mod-viewer.appspot.com/github.com/DataWorkbench/glog@v0.0.0-20220707065325-9c6ad406158f/pkg/buffer/buffer_test.go#L52


```go
    46  func BenchmarkBuffers(b *testing.B) {
    47  	// Because we use the strconv.AppendFoo functions so liberally, we can't
    48  	// use the standard library's bytes.Buffer anyways (without incurring a
    49  	// bunch of extra allocations). Nevertheless, let's make sure that we're
    50  	// not losing any precious nanoseconds.
    51  	str := strings.Repeat("a", 1024)
    52  	slice := make([]byte, 1024)
    53  	buf := bytes.NewBuffer(slice)
    54  	custom := NewPool().Get()
    55  	b.Run("ByteSlice", func(b *testing.B) {
    56  		for i := 0; i < b.N; i++ {
    57  			slice = append(slice, str...)
    58  			slice = slice[:0]
    59  		}
    60  	})
    61  	b.Run("BytesBuffer", func(b *testing.B) {
    62  		for i := 0; i < b.N; i++ {
    63  			buf.WriteString(str)
    64  			buf.Reset()
    65  		}
    66  	})
    67  	b.Run("CustomBuffer", func(b *testing.B) {
    68  		for i := 0; i < b.N; i++ {
    69  			custom.AppendString(str)
    70  			custom.Reset()
    71  		}
    72  	})
    73  }
```


Also a very standard case of error


<br>
<br>



## 51. 52. 54 (false positive: false)

https://go-mod-viewer.appspot.com/github.com/Davincible/goinsta/v3@v3.2.6/comments.go#L208

https://go-mod-viewer.appspot.com/github.com/FactomProject/basen@v0.0.0-20150613233007-fe3947df716e/basen.go#L117

https://go-mod-viewer.appspot.com/github.com/Finschia/finschia-sdk@v0.49.1/x/auth/vesting/types/period.go#L53


A very standard case of error


<br>
<br>


## 53. 55  (false positive: todo) The same as #48

53: https://go-mod-viewer.appspot.com/github.com/Finschia/finschia-sdk@v0.49.1/crypto/keys/secp256k1/secp256k1_internal_test.go#L13

```go

    12  func Test_genPrivKey(t *testing.T) {
    13  	empty := make([]byte, 32)
    14  	oneB := big.NewInt(1).Bytes()
    15  	onePadded := make([]byte, 32)
    16  	copy(onePadded[32-len(oneB):32], oneB)
    17  	t.Logf("one padded: %v, len=%v", onePadded, len(onePadded))
    18  
    19  	validOne := append(empty, onePadded...)
    20  	tests := []struct {
    21  		name        string
    22  		notSoRand   []byte
    23  		shouldPanic bool
    24  	}{
    25  		{"empty bytes (panics because 1st 32 bytes are zero and 0 is not a valid field element)", empty, true},
    26  		{"curve order: N", btcSecp256k1.S256().N.Bytes(), true},
    27  		{"valid because 0 < 1 < N", validOne, false},
    28  	}
    29  	for _, tt := range tests {
    30  		t.Run(tt.name, func(t *testing.T) {
    31  			if tt.shouldPanic {
    32  				require.Panics(t, func() {
    33  					genPrivKey(bytes.NewReader(tt.notSoRand))
    34  				})
    35  				return
    36  			}
    37  			got := genPrivKey(bytes.NewReader(tt.notSoRand))
    38  			fe := new(big.Int).SetBytes(got)
    39  			require.True(t, fe.Cmp(btcSecp256k1.S256().N) < 0)
    40  			require.True(t, fe.Sign() > 0)
    41  		})
    42  	}
    43  }
```



55: https://go-mod-viewer.appspot.com/github.com/Finschia/ostracon@v1.1.5/crypto/secp256k1/secp256k1_internal_test.go#L15


```go
    13  func Test_genPrivKey(t *testing.T) {
    14  
    15  	empty := make([]byte, 32)
    16  	oneB := big.NewInt(1).Bytes()
    17  	onePadded := make([]byte, 32)
    18  	copy(onePadded[32-len(oneB):32], oneB)
    19  	t.Logf("one padded: %v, len=%v", onePadded, len(onePadded))
    20  
    21  	validOne := append(empty, onePadded...)
    22  	tests := []struct {
    23  		name        string
    24  		notSoRand   []byte
    25  		shouldPanic bool
    26  	}{
    27  		{"empty bytes (panics because 1st 32 bytes are zero and 0 is not a valid field element)", empty, true},
    28  		{"curve order: N", secp256k1.S256().N.Bytes(), true},
    29  		{"valid because 0 < 1 < N", validOne, false},
    30  	}
    31  	for _, tt := range tests {
    32  		tt := tt
    33  		t.Run(tt.name, func(t *testing.T) {
    34  			if tt.shouldPanic {
    35  				require.Panics(t, func() {
    36  					genPrivKey(bytes.NewReader(tt.notSoRand))
    37  				})
    38  				return
    39  			}
    40  			got := genPrivKey(bytes.NewReader(tt.notSoRand))
    41  			fe := new(big.Int).SetBytes(got[:])
    42  			require.True(t, fe.Cmp(secp256k1.S256().N) < 0)
    43  			require.True(t, fe.Sign() > 0)
    44  		})
    45  	}
    46  }

```

The same as #48


 <br>
 <br>



## 56~59  (false positive: false)



https://go-mod-viewer.appspot.com/github.com/GeoNet/kit@v0.0.0-20241014234258-12f366e1c4f5/aws/s3/s3_concurrent_test.go#L70
https://go-mod-viewer.appspot.com/github.com/GoogleCloudPlatform/terraformer@v0.8.18/terraformutils/providers_mapping.go#L55
https://go-mod-viewer.appspot.com/github.com/GoogleContainerTools/skaffold/v2@v2.13.2/pkg/skaffold/tag/tagger_mux.go#L44
https://go-mod-viewer.appspot.com/github.com/GoogleContainerTools/skaffold@v1.39.18/pkg/skaffold/tag/tagger_mux.go#L44


A very standard case of error



## 60.(false positive: todo) https://go-mod-viewer.appspot.com/github.com/Gravity-Bridge/Gravity-Bridge/module@v1.4.1/x/gravity/types/key.go#L237


```go
   231  // GetOutgoingTxPoolKey returns the following key format
   232  // prefix	feeContract		feeAmount     id
   233  // [0x6][0xc783df8a850f42e7F7e57013759C285caa701eB6][1000000000][0 0 0 0 0 0 0 1]
   234  func GetOutgoingTxPoolKey(fee InternalERC20Token, id uint64) string {
   235  	// sdkInts have a size limit of 255 bits or 32 bytes
   236  	// therefore this will never panic and is always safe
   237  	amount := make([]byte, 32)
   238  	amount = fee.Amount.BigInt().FillBytes(amount)
   239  
   240  	a := append(amount, UInt64Bytes(id)...)
   241  	b := append([]byte(fee.Contract.GetAddress()), a...)
   242  	r := append([]byte(OutgoingTXPoolKey), b...)
   243  	return ConvertByteArrToString(r)
   244  }
```

`fee.Amount.BigInt().FillBytes(sli)` is a user-defined function



<br>
<br>


## 61.64,65   (false positive: false)

https://go-mod-viewer.appspot.com/github.com/Gui774ume/ebpf@v0.0.0-20200411100314-4233cdb60f05/utsname_int8.go#L6

https://go-mod-viewer.appspot.com/github.com/InjectiveLabs/sdk-go@v1.53.0/client/core/tokens_file_loader_test.go#L14

https://go-mod-viewer.appspot.com/github.com/JanDeVisser/grumble@v0.0.0-20200603144613-bce115edd0f2/kind.go#L451

https://go-mod-viewer.appspot.com/github.com/LagrangeDev/LagrangeGo@v0.1.0/utils/crypto/aes.go#L10


A very standard case of error



## 62. 63 (false positive: todo)




https://go-mod-viewer.appspot.com/github.com/Hyperledger-TWGC/tjfoc-gm@v1.4.0/sm4/sm4_gcm.go#L144

https://go-mod-viewer.appspot.com/github.com/Hyperledger-TWGC/tjfoc-gm@v1.4.0/sm4/sm4_gcm.go#L156


There is a copy operation, which should have been excluded. We need to see why it is still detected




## 66. (false positive: true)


https://go-mod-viewer.appspot.com/github.com/LagrangeDev/LagrangeGo@v0.1.0/utils/crypto/aes.go#L10


```go
     9  func AESGCMEncrypt(data []byte, key []byte) ([]byte, error) {
    10  	nonce := make([]byte, 12)
    11  	if _, err := rand.Read(nonce); err != nil {
    12  		return nil, err
    13  	}
    14  
    15  	block, err := aes.NewCipher(key)
    16  	if err != nil {
    17  		return nil, err
    18  	}
    19  	aead, err := cipher.NewGCM(block)
    20  	if err != nil {
    21  		return nil, err
    22  	}
    23  	ciphertext := aead.Seal(nil, nonce, data, nil)
    24  
    25  	return append(nonce, ciphertext...), nil
    26  }
```


`rand.Read` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it




## 67.  (false positive: false)  https://go-mod-viewer.appspot.com/github.com/Laisky/zap@v1.27.0/buffer/buffer_test.go#L74


```go

    68  func BenchmarkBuffers(b *testing.B) {
    69  	// Because we use the strconv.AppendFoo functions so liberally, we can't
    70  	// use the standard library's bytes.Buffer anyways (without incurring a
    71  	// bunch of extra allocations). Nevertheless, let's make sure that we're
    72  	// not losing any precious nanoseconds.
    73  	str := strings.Repeat("a", 1024)
    74  	slice := make([]byte, 1024)
    75  	buf := bytes.NewBuffer(slice)
    76  	custom := NewPool().Get()
    77  	b.Run("ByteSlice", func(b *testing.B) {
    78  		for i := 0; i < b.N; i++ {
    79  			slice = append(slice, str...)
    80  			slice = slice[:0]
    81  		}
    82  	})
    83  	b.Run("BytesBuffer", func(b *testing.B) {
    84  		for i := 0; i < b.N; i++ {
    85  			buf.WriteString(str)
    86  			buf.Reset()
    87  		}
    88  	})
    89  	b.Run("CustomBuffer", func(b *testing.B) {
    90  		for i := 0; i < b.N; i++ {
    91  			custom.AppendString(str)
    92  			custom.Reset()
    93  		}
    94  	})
    95  }
```


## 68. 69. 70. 71~75, 76  (false positive: false) 



https://go-mod-viewer.appspot.com/github.com/MetalBlockchain/metalgo@v1.11.9/x/sync/sync_test.go#L490
https://go-mod-viewer.appspot.com/github.com/Microsoft/azure-vhd-utils@v0.0.0-20230613175315-7c30a3748a1b/vhdcore/diskstream/diskstream.go#L155
https://go-mod-viewer.appspot.com/github.com/Mrs4s/MiraiGo@v0.0.0-20240226124653-54bdd873e3fe/client/guild_eventflow.go#L37


71~75:
https://go-mod-viewer.appspot.com/github.com/ONSdigital/dp-kafka/v2@v2.8.0/avro/avro.go#L356
https://go-mod-viewer.appspot.com/github.com/ONSdigital/dp-kafka/v3@v3.10.0/avro/avro.go#L356
https://go-mod-viewer.appspot.com/github.com/ONSdigital/dp-kafka/v4@v4.1.0/avro/avro.go#L356
https://go-mod-viewer.appspot.com/github.com/ONSdigital/go-ns@v0.0.0-20210916104633-ac1c1c52327e/avro/avro.go#L350
https://go-mod-viewer.appspot.com/github.com/ONSdigital/go-ns@v0.0.0-20210916104633-ac1c1c52327e/avro/avro.go#L476


https://go-mod-viewer.appspot.com/github.com/Pallinder/go-randomdata@v1.2.0/random_data_test.go#L47

A very standard case of error


<br>
<br>


## 77.78.  (false positive: true)  



https://go-mod-viewer.appspot.com/github.com/PretendoNetwork/nex-go/v2@v2.0.5/kerberos.go#L51




```go
    47  
    48  // Encrypt encrypts the given buffer and appends an HMAC checksum for integrity
    49  func (ke *KerberosEncryption) Encrypt(buffer []byte) []byte {
    50  	cipher, _ := rc4.NewCipher(ke.key)
    51  	encrypted := make([]byte, len(buffer))
    52  
    53  	cipher.XORKeyStream(encrypted, buffer)
    54  
    55  	mac := hmac.New(md5.New, ke.key)
    56  
    57  	mac.Write(encrypted)
    58  
    59  	checksum := mac.Sum(nil)
    60  
    61  	return append(encrypted, checksum...)
    62  }
```



https://go-mod-viewer.appspot.com/github.com/PretendoNetwork/nex-go@v1.0.41/kerberos.go#L20

```go
    18  // Encrypt will encrypt the given data using Kerberos
    19  func (encryption *KerberosEncryption) Encrypt(buffer []byte) []byte {
    20  	encrypted := make([]byte, len(buffer))
    21  	encryption.cipher.XORKeyStream(encrypted, buffer)
    22  
    23  	mac := hmac.New(md5.New, []byte(encryption.key))
    24  	mac.Write(encrypted)
    25  	hmac := mac.Sum(nil)
    26  
    27  	return append(encrypted, hmac...)
    28  }

```



`cipher.XORKeyStream`  should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it




## 79. 80 (false positive: todo)  


https://go-mod-viewer.appspot.com/github.com/ProtonMail/go-crypto@v1.0.0/ocb/ocb.go#L156


https://go-mod-viewer.appspot.com/github.com/ProtonMail/go-crypto@v1.0.0/openpgp/aes/keywrap/keywrap_test.go#L66


```go
    64  // Test wrap error cases.
    65  func TestWrapError(t *testing.T) {
    66  	plaintext := make([]byte, 7)
    67  	key := make([]byte, 32)
    68  	_, err := Wrap(key, plaintext)
    69  	if err != ErrWrapPlaintext {
    70  		t.Fatalf("keywrap: expected Wrap to fail with %v, but have err=%v", ErrWrapPlaintext, err)
    71  	}
    72  
    73  	plaintext = append(plaintext, byte(0))
    74  	_, err = Wrap(key[:31], plaintext)
    75  	if err != ErrInvalidKey {
    76  		t.Fatalf("keywrap: expected Wrap to fail with %v, but have err=%v", ErrInvalidKey, err)
    77  	}
    78  }
```

`Not easy to judge`




## 81 ~85  (false positive: false)  


https://go-mod-viewer.appspot.com/github.com/TencentBlueKing/iam-go-sdk@v0.1.6/expression/expr_test.go#L826
https://go-mod-viewer.appspot.com/github.com/TrueBlocks/trueblocks-core/src/apps/chifra@v0.0.0-20241022031540-b362680128f7/pkg/filter/filter.go#L115
https://go-mod-viewer.appspot.com/github.com/Wifx/gonetworkmanager/v2@v2.1.0/IP4Config.go#L255
https://go-mod-viewer.appspot.com/github.com/XiaoMi/Gaea@v1.2.5/mysql/conn.go#L233
https://go-mod-viewer.appspot.com/github.com/aldelo/common@v1.5.1/wrapper/dynamodb/crud.go#L725


```go
   825  func BenchmarkExprCellIn(b *testing.B) {
   826  	ids := make([]string, 10000)
   827  	for i := 0; i < 9999; i++ {
   828  		ids = append(ids, strconv.Itoa(i))
   829  	}
   830  	ids = append(ids, "world")
   831  
   832  	e := &expression.ExprCell{
   833  		OP:    operator.In,
   834  		Field: "obj.name",
   835  		// Value: []string{"hello", "world"},
   836  		Value: ids,
   837  	}
   838  
   839  	o := expression.NewObjectSet()
   840  	o.Set("obj", map[string]interface{}{
   841  		"name": "world",
   842  	})
   843  
   844  	b.ReportAllocs()
   845  	b.ResetTimer()
   846  	for i := 0; i < b.N; i++ {
   847  		e.Eval(o)
   848  	}
   849  }
```

```go
   114  func (f *AppearanceFilter) ApplyLogFilter(log *types.Log, addrArray []base.Address) bool {
   115  	haystack := make([]byte, 66*len(log.Topics)+len(log.Data))
   116  	haystack = append(haystack, log.Address.Hex()[2:]...)
   117  	for _, topic := range log.Topics {
   118  		haystack = append(haystack, topic.Hex()[2:]...)
   119  	}
   120  	haystack = append(haystack, log.Data[2:]...)
   121  
   122  	for _, addr := range addrArray {
   123  		if strings.Contains(string(haystack), addr.Hex()[2:]) {
   124  			return true
   125  		}
   126  	}
   127  	return false
   128  }
```



A very standard case of error



## 86 (false positive: true)   https://go-mod-viewer.appspot.com/github.com/algorand/go-algorand-sdk@v1.24.0/templates/template.go#L71


```go
  38  func inject(original []byte, offsets []uint64, values []interface{}) (result []byte, err error) {
    39  	result = original
    40  	if len(offsets) != len(values) {
    41  		err = fmt.Errorf("length of offsets %v does not match length of replacement values %v", len(offsets), len(values))
    42  		return
    43  	}
    44  
    45  	for i, value := range values {
    46  		decodedLength := 0
    47  		if valueAsUint, ok := value.(uint64); ok {
    48  			// make the exact minimum buffer needed and no larger
    49  			// because otherwise there will be extra bytes inserted
    50  			sizingBuffer := make([]byte, binary.MaxVarintLen64)
    51  			decodedLength = binary.PutUvarint(sizingBuffer, valueAsUint)
    52  			fillingBuffer := make([]byte, decodedLength)
    53  			decodedLength = binary.PutUvarint(fillingBuffer, valueAsUint)
    54  			result = replace(result, fillingBuffer, offsets[i], uint64(1))
    55  		} else if address, ok := value.(types.Address); ok {
    56  			addressLen := uint64(32)
    57  			addressBytes := make([]byte, addressLen)
    58  			copy(addressBytes, address[:])
    59  			result = replace(result, addressBytes, offsets[i], addressLen)
    60  		} else if b64string, ok := value.(string); ok {
    61  			decodeBytes, decodeErr := base64.StdEncoding.DecodeString(b64string)
    62  			if decodeErr != nil {
    63  				err = decodeErr
    64  				return
    65  			}
    66  			// do the same thing as in the uint64 case to trim empty bytes:
    67  			// first fill one buffer to figure out the number of bytes to be written,
    68  			// then fill a second buffer of exactly the right size
    69  			sizingBuffer := make([]byte, binary.MaxVarintLen64)
    70  			numBytesWritten := binary.PutUvarint(sizingBuffer, uint64(len(decodeBytes)))
    71  			fillingBuffer := make([]byte, numBytesWritten)
    72  			binary.PutUvarint(fillingBuffer, uint64(len(decodeBytes))) // indicate length of b64 bytes
    73  			// want to write [length of b64 bytes, b64 bytes]
    74  			decodeBytes = append(fillingBuffer, decodeBytes...)
    75  			result = replace(result, decodeBytes, offsets[i], uint64(33))
    76  		}
    77  
    78  		if decodedLength != 0 {
    79  			for j := range offsets {
    80  				offsets[j] = offsets[j] + uint64(decodedLength) - 1
    81  			}
    82  		}
    83  	}
    84  	return
    85  }
```


`binary.PutUvarint` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it



## 87 (false positive: todo)  https://go-mod-viewer.appspot.com/github.com/alimy/mir/v4@v4.1.0/internal/utils/utils.go#L20


```go
    13  // UpperFirst make first rune upper in s string
    14  func UpperFirst(s string) string {
    15  	firstRune, size := utf8.DecodeRuneInString(s)
    16  	if unicode.IsUpper(firstRune) {
    17  		return s
    18  	}
    19  	// encode upperFirst to []byte,use max byte for contain unicode
    20  	res := make([]byte, len(s))
    21  	upperRune := unicode.ToUpper(firstRune)
    22  	number := utf8.EncodeRune(res, upperRune)
    23  	res = res[:number]
    24  	res = append(res, s[size:]...)
    25  	return string(res)
    26  }
```

should use `make([]byte, 0, len(s))`



## 88. 89. 90. (false positive: false)  



https://go-mod-viewer.appspot.com/github.com/ammario/ipisp@v1.0.0/dns_client.go#L24
https://go-mod-viewer.appspot.com/github.com/ammario/ipisp@v1.0.0/dns_client.go#L93
https://go-mod-viewer.appspot.com/github.com/angelofallars/htmx-go@v0.5.0/swap.go#L78

A very standard case of error




## 91. 92   (false positive: false)  


https://go-mod-viewer.appspot.com/github.com/apache/arrow/go/v10@v10.0.1/arrow/scalar/parse.go#L347

https://go-mod-viewer.appspot.com/github.com/apache/arrow/go/v10@v10.0.1/arrow/scalar/parse.go#L348



A very standard case of error


## 93.97 (false positive: todo) 


https://go-mod-viewer.appspot.com/github.com/apache/arrow/go/v10@v10.0.1/parquet/internal/encoding/delta_bit_packing.go#L440

https://go-mod-viewer.appspot.com/github.com/apache/arrow/go/v12@v12.0.1/parquet/internal/encoding/delta_bit_packing.go#L438



```go
   427  // FlushValues flushes any remaining data and returns the finished encoded buffer
   428  // or returns nil and any error encountered during flushing.
   429  func (enc *deltaBitPackEncoder) FlushValues() (Buffer, error) {
   430  	if enc.bitWriter != nil {
   431  		// write any remaining values
   432  		enc.flushBlock()
   433  		enc.bitWriter.Flush(true)
   434  	} else {
   435  		enc.blockSize = defaultBlockSize
   436  		enc.numMiniBlocks = defaultNumMiniBlocks
   437  		enc.miniBlockSize = defaultNumValuesPerMini
   438  	}
   439  
   440  	buffer := make([]byte, maxHeaderWriterSize)
   441  	headerWriter := utils.NewBitWriter(utils.NewWriterAtBuffer(buffer))
   442  
   443  	headerWriter.WriteVlqInt(uint64(enc.blockSize))
   444  	headerWriter.WriteVlqInt(uint64(enc.numMiniBlocks))
   445  	headerWriter.WriteVlqInt(uint64(enc.totalVals))
   446  	headerWriter.WriteZigZagVlqInt(int64(enc.firstVal))
   447  	headerWriter.Flush(false)
   448  
   449  	buffer = buffer[:headerWriter.Written()]
   450  	enc.totalVals = 0
   451  
   452  	if enc.bitWriter != nil {
   453  		flushed := enc.sink.Finish()
   454  		defer flushed.Release()
   455  
   456  		buffer = append(buffer, flushed.Buf()[:enc.bitWriter.Written()]...)
   457  	}
   458  	return poolBuffer{memory.NewBufferBytes(buffer)}, nil
   459  }
```

user-defined function.  but probably a bug.


## 94.98. (false positive: todo)   


https://go-mod-viewer.appspot.com/github.com/apache/arrow/go/v10@v10.0.1/parquet/internal/utils/bit_reader_test.go#L535
https://go-mod-viewer.appspot.com/github.com/apache/arrow/go/v12@v12.0.1/parquet/internal/utils/bit_reader_test.go#L535


```go
   530  func (r *RLERandomSuite) TestRandomSequences() {
   531  	const niters = 50
   532  	const ngroups = 1000
   533  	const maxgroup = 16
   534  
   535  	values := make([]uint64, ngroups+maxgroup)
   536  	seed := rand.Uint64() ^ (rand.Uint64() << 32)
   537  	gen := rand.New(rand.NewSource(seed))
   538  
   539  	for itr := 0; itr < niters; itr++ {
   540  		parity := false
   541  		values = values[:0]
   542  
   543  		for i := 0; i < ngroups; i++ {
   544  			groupsize := gen.Intn(19) + 1
   545  			if groupsize > maxgroup {
   546  				groupsize = 1
   547  			}
   548  
   549  			v := uint64(0)
   550  			if parity {
   551  				v = 1
   552  			}
   553  			for j := 0; j < groupsize; j++ {
   554  				values = append(values, v)
   555  			}
   556  			parity = !parity
   557  		}
   558  		r.Require().Truef(r.checkRoundTrip(values, bits.Len(uint(len(values)))), "failing seed: %d", seed)
   559  	}
   560  }
```


## 95.99.100 (false positive: false) 


A very standard case of error


https://go-mod-viewer.appspot.com/github.com/apache/arrow/go/v12@v12.0.1/arrow/scalar/parse.go#L348

https://go-mod-viewer.appspot.com/github.com/apache/arrow/go/v13@v13.0.0/arrow/scalar/parse.go#L348

https://go-mod-viewer.appspot.com/github.com/apache/arrow/go/v13@v13.0.0/arrow/scalar/parse.go#L349




---




## Then randomly select from 100-850


## a. (false positive: false)  https://go-mod-viewer.appspot.com/github.com/astaxie/beego@v1.12.3/plugins/apiauth/apiauth.go#L138

```go
   135  // Signature used to generate signature with the appsecret/method/params/RequestURI
   136  func Signature(appsecret, method string, params url.Values, RequestURL string) (result string) {
   137  	var b bytes.Buffer
   138  	keys := make([]string, len(params))
   139  	pa := make(map[string]string)
   140  	for k, v := range params {
   141  		pa[k] = v[0]
   142  		keys = append(keys, k)
   143  	}
   144  
   145  	sort.Strings(keys)
   146  
   147  	for _, key := range keys {
   148  		if key == "signature" {
   149  			continue
   150  		}
   151  
   152  		val := pa[key]
   153  		if key != "" && val != "" {
   154  			b.WriteString(key)
   155  			b.WriteString(val)
   156  		}
   157  	}
   158  
   159  	stringToSign := fmt.Sprintf("%v\n%v\n%v\n", method, b.String(), RequestURL)
   160  
   161  	sha256 := sha256.New
   162  	hash := hmac.New(sha256, []byte(appsecret))
   163  	hash.Write([]byte(stringToSign))
   164  	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
   165  }
```


A very standard case of error




## b. (false positive: false)  https://go-mod-viewer.appspot.com/github.com/ava-labs/avalanche-cli@v1.7.7/cmd/blockchaincmd/create.go#L421


https://go-mod-viewer.appspot.com/github.com/ava-labs/avalanche-cli@v1.7.7/cmd/blockchaincmd/create.go#L421

```go
   413  func sendMetrics(cmd *cobra.Command, repoName, blockchainName string) error {
   414  	flags := make(map[string]string)
   415  	flags[constants.SubnetType] = repoName
   416  	genesis, err := app.LoadEvmGenesis(blockchainName)
   417  	if err != nil {
   418  		return err
   419  	}
   420  	conf := genesis.Config.GenesisPrecompiles
   421  	precompiles := make([]string, 6)
   422  	for precompileName := range conf {
   423  		precompileTag := "precompile-" + precompileName
   424  		flags[precompileTag] = precompileName
   425  		precompiles = append(precompiles, precompileName)
   426  	}
   427  	numAirdropAddresses := len(genesis.Alloc)
   428  	for address := range genesis.Alloc {
   429  		if address.String() != vm.PrefundedEwoqAddress.String() {
   430  			precompileTag := "precompile-" + constants.CustomAirdrop
   431  			flags[precompileTag] = constants.CustomAirdrop
   432  			precompiles = append(precompiles, constants.CustomAirdrop)
   433  			break
   434  		}
   435  	}
   436  	sort.Strings(precompiles)
   437  	precompilesJoined := strings.Join(precompiles, ",")
   438  	flags[constants.PrecompileType] = precompilesJoined
   439  	flags[constants.NumberOfAirdrops] = strconv.Itoa(numAirdropAddresses)
   440  	metrics.HandleTracking(cmd, constants.MetricsSubnetCreateCommand, app, flags)
   441  	return nil
   442  }
```

A very standard case of error




## c. (false positive: false) https://go-mod-viewer.appspot.com/github.com/coming-chat/go-aptos@v0.0.0-20240226115831-c2468230eadc/transaction_builder/remote_builder.go#L91



A very standard case of error




## d. (false positive: todo) https://go-mod-viewer.appspot.com/github.com/consensys/gnark-crypto@v0.14.0/ecc/bls12-377/twistededwards/eddsa/eddsa.go#L180


```go
118  // Sign sign a sequence of field elements
   119  // For arbitrary strings use fr.Hash first
   120  // Pure Eddsa version (see https://tools.ietf.org/html/rfc8032#page-8)
   121  func (privKey *PrivateKey) Sign(message []byte, hFunc hash.Hash) ([]byte, error) {
   122  
   123  	// hFunc cannot be nil.
   124  	// We need a hash function for the Fiat-Shamir.
   125  	if hFunc == nil {
   126  		return nil, errHashNeeded
   127  	}
   128  
   129  	curveParams := twistededwards.GetEdwardsCurve()
   130  
   131  	var res Signature
   132  
   133  	// blinding factor for the private key
   134  	// blindingFactorBigInt must be the same size as the private key,
   135  	// blindingFactorBigInt = h(randomness_source||message)[:sizeFr]
   136  	var blindingFactorBigInt big.Int
   137  
   138  	// randSrc = privKey.randSrc || msg (-> message = MSB message .. LSB message)
   139  	randSrc := make([]byte, 32+len(message))
   140  	copy(randSrc, privKey.randSrc[:])
   141  	copy(randSrc[32:], message)
   142  
   143  	// randBytes = H(randSrc)
   144  	blindingFactorBytes := blake2b.Sum512(randSrc[:]) // TODO ensures that the hash used to build the key and the one used here is the same
   145  	blindingFactorBigInt.SetBytes(blindingFactorBytes[:sizeFr])
   146  
   147  	// compute R = randScalar*Base
   148  	res.R.ScalarMultiplication(&curveParams.Base, &blindingFactorBigInt)
   149  	if !res.R.IsOnCurve() {
   150  		return nil, errNotOnCurve
   151  	}
   152  
   153  	// compute H(R, A, M), all parameters in data are in Montgomery form
   154  	hFunc.Reset()
   155  
   156  	resRX := res.R.X.Bytes()
   157  	resRY := res.R.Y.Bytes()
   158  	resAX := privKey.PublicKey.A.X.Bytes()
   159  	resAY := privKey.PublicKey.A.Y.Bytes()
   160  	toWrite := [][]byte{resRX[:], resRY[:], resAX[:], resAY[:], message}
   161  	for _, bytes := range toWrite {
   162  		if _, err := hFunc.Write(bytes); err != nil {
   163  			return nil, err
   164  		}
   165  	}
   166  
   167  	var hramInt big.Int
   168  	hramBin := hFunc.Sum(nil)
   169  	hramInt.SetBytes(hramBin)
   170  
   171  	// Compute s = randScalarInt + H(R,A,M)*S
   172  	// going with big int to do ops mod curve order
   173  	var bscalar, bs big.Int
   174  	bscalar.SetBytes(privKey.scalar[:])
   175  	bs.Mul(&hramInt, &bscalar).
   176  		Add(&bs, &blindingFactorBigInt).
   177  		Mod(&bs, &curveParams.Order)
   178  	sb := bs.Bytes()
   179  	if len(sb) < sizeFr {
   180  		offset := make([]byte, sizeFr-len(sb))
   181  		sb = append(offset, sb...)
   182  	}
   183  	copy(res.S[:], sb[:])
   184  
   185  	return res.Bytes(), nil
   186  }
```

`Need to consider the order of copy and append`



## e. (false positive: false) https://go-mod-viewer.appspot.com/github.com/consensys/gnark@v0.11.0/profile/internal/graph/graph.go#L441


```go
399  func newTree(prof *profile.Profile, o *Options) (g *Graph) {
   400  	parentNodeMap := make(map[*Node]NodeMap, len(prof.Sample))
   401  	for _, sample := range prof.Sample {
   402  		var w, dw int64
   403  		w = o.SampleValue(sample.Value)
   404  		if o.SampleMeanDivisor != nil {
   405  			dw = o.SampleMeanDivisor(sample.Value)
   406  		}
   407  		if dw == 0 && w == 0 {
   408  			continue
   409  		}
   410  		var parent *Node
   411  		labels := joinLabels(sample)
   412  		// Group the sample frames, based on a per-node map.
   413  		for i := len(sample.Location) - 1; i >= 0; i-- {
   414  			l := sample.Location[i]
   415  			lines := l.Line
   416  			if len(lines) == 0 {
   417  				lines = []profile.Line{{}} // Create empty line to include location info.
   418  			}
   419  			for lidx := len(lines) - 1; lidx >= 0; lidx-- {
   420  				nodeMap := parentNodeMap[parent]
   421  				if nodeMap == nil {
   422  					nodeMap = make(NodeMap)
   423  					parentNodeMap[parent] = nodeMap
   424  				}
   425  				n := nodeMap.findOrInsertLine(l, lines[lidx], o)
   426  				if n == nil {
   427  					continue
   428  				}
   429  				n.addSample(dw, w, labels, sample.NumLabel, sample.NumUnit, o.FormatTag, false)
   430  				if parent != nil {
   431  					parent.AddToEdgeDiv(n, dw, w, false, lidx != len(lines)-1)
   432  				}
   433  				parent = n
   434  			}
   435  		}
   436  		if parent != nil {
   437  			parent.addSample(dw, w, labels, sample.NumLabel, sample.NumUnit, o.FormatTag, true)
   438  		}
   439  	}
   440  
   441  	nodes := make(Nodes, len(prof.Location))
   442  	for _, nm := range parentNodeMap {
   443  		nodes = append(nodes, nm.nodes()...)
   444  	}
   445  	return selectNodesForGraph(nodes, o.DropNegative)
   446  }
```

A very standard case of error



## f.(false positive: false)  https://go-mod-viewer.appspot.com/github.com/cosmos/cosmos-sdk@v0.50.10/x/auth/vesting/types/period.go#L45


```go
   43  // String implements the fmt.Stringer interface
    44  func (p Periods) String() string {
    45  	periodsListString := make([]string, len(p))
    46  	for _, period := range p {
    47  		periodsListString = append(periodsListString, period.String())
    48  	}
    49  
    50  	return strings.TrimSpace(fmt.Sprintf(`Vesting Periods:
    51  		%s`, strings.Join(periodsListString, ", ")))
    52  }
```

A very standard case of error



## g.  (false positive: todo)  https://go-mod-viewer.appspot.com/github.com/costinm/meshauth@v0.0.0-20240803190121-2a6dfc0e888a/sign.go#L96


```go
    90  func SignHash(data []byte, p crypto.PrivateKey) []byte {
    91  	var sig []byte
    92  	if ec, ok := p.(*ecdsa.PrivateKey); ok {
    93  		if r, s, err := ecdsa.Sign(rand.Reader, ec,data ); err == nil {
    94  			// Vapid key is 32 bytes
    95  			keyBytes := 32
    96  			sig = make([]byte, 2*keyBytes)
    97  
    98  			rBytes := r.Bytes()
    99  			rBytesPadded := make([]byte, keyBytes)
   100  			copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)
   101  
   102  			sBytes := s.Bytes()
   103  			sBytesPadded := make([]byte, keyBytes)
   104  			copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)
   105  
   106  			sig = append(sig[:0], rBytesPadded...)
   107  			sig = append(sig, sBytesPadded...)
   108  
   109  		}
   110  	} else if ed, ok := p.(ed25519.PrivateKey); ok {
   111  		sig, _ = ed.Sign(rand.Reader, data, nil)
   112  	}
   113  
   114  	return sig
   115  }
```


<br>
<br>


## h.  (false positive: true)  https://go-mod-viewer.appspot.com/github.com/gagliardetto/solana-go@v1.11.0/vault/passphrase.go#L46


```go
    40  func (b *PassphraseBoxer) Seal(in []byte) (string, error) {
    41  	var nonce [nonceLength]byte
    42  	if _, err := io.ReadFull(crypto_rand.Reader, nonce[:]); err != nil {
    43  		return "", err
    44  	}
    45  
    46  	salt := make([]byte, saltLength)
    47  	if _, err := io.ReadFull(crypto_rand.Reader, salt); err != nil {
    48  		return "", err
    49  	}
    50  	secretKey := deriveKey(b.passphrase, salt)
    51  	prefix := append(salt, nonce[:]...)
    52  
    53  	cipherText := secretbox.Seal(prefix, in, &nonce, &secretKey)
    54  
    55  	return base64.RawStdEncoding.EncodeToString(cipherText), nil
    56  }
```

`rand.Read` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it




## i.  (false positive: false)  https://go-mod-viewer.appspot.com/github.com/getgauge/gauge@v1.6.9/cmd/list.go#L128


```go
  126  func uniqueNonEmptyElementsOf(input []string) []string {
   127  	unique := make(map[string]bool, len(input))
   128  	us := make([]string, len(unique))
   129  	for _, elem := range input {
   130  		if len(elem) != 0 && !unique[elem] {
   131  			us = append(us, elem)
   132  			unique[elem] = true
   133  		}
   134  	}
   135  
   136  	return us
   137  }
```

A very standard case of error




## j.  (false positive: false)  https://go-mod-viewer.appspot.com/github.com/go-alive/cli@v0.0.0-20210505055417-57ebdd3d2c3e/errors.go#L44


```go
    42  // Errors returns a copy of the errors slice
    43  func (m *multiError) Errors() []error {
    44  	errs := make([]error, len(*m))
    45  	for _, err := range *m {
    46  		errs = append(errs, err)
    47  	}
    48  	return errs
    49  }
```

A very standard case of error




## k.  (false positive: false)  https://go-mod-viewer.appspot.com/github.com/go-chef/chef@v0.30.1/environment.go#L32


```go
  31  func strMapToStr(e map[string]string) (out string) {
    32  	keys := make([]string, len(e))
    33  	for k, _ := range e {
    34  		keys = append(keys, k)
    35  	}
    36  	sort.Strings(keys)
    37  	for _, k := range keys {
    38  		if k == "" {
    39  			continue
    40  		}
    41  		out += fmt.Sprintf("%s => %s\n", k, e[k])
    42  	}
    43  	return
    44  }
```

A very standard case of error





## l.  (false positive: false)  https://go-mod-viewer.appspot.com/github.com/go-graphite/carbonapi@v0.17.0/zipper/protocols/irondb/irondb_group.go#L380



A very standard case of error




## m. (false positive: false) https://go-mod-viewer.appspot.com/github.com/grafana/sobek@v0.0.0-20241023145759-2dc9daf5bfa2/modules_integration_test.go#L336

```go
335  func (s *cyclicModuleImpl) GetExportedNames(callback func([]string), records ...sobek.ModuleRecord) bool {
   336  	result := make([]string, len(s.exports))
   337  	for k := range s.exports {
   338  		result = append(result, k)
   339  	}
   340  	sort.Strings(result)
   341  	callback(result)
   342  	return true
   343  }
```

A very standard case of error




## n. (false positive: false) https://go-mod-viewer.appspot.com/github.com/iotexproject/iotex-core@v1.14.2/ioctl/cmd/ws/wsdeviceapprove.go#L64


```go
    58  func approveProjectDevice(projectID uint64, devices string) (string, error) {
    59  	deviceArr := []string{devices}
    60  	if strings.Contains(devices, ",") {
    61  		deviceArr = strings.Split(devices, ",")
    62  	}
    63  
    64  	deviceAddress := make([]common.Address, len(deviceArr))
    65  	for _, device := range deviceArr {
    66  		addr, err := address.FromString(device)
    67  		if err != nil {
    68  			return "", errors.Wrapf(err, "invalid device address: %s", device)
    69  		}
    70  		deviceAddress = append(deviceAddress, common.BytesToAddress(addr.Bytes()))
    71  	}
    72  
    73  	caller, err := NewContractCaller(projectDeviceABI, projectDeviceAddress)
    74  	if err != nil {
    75  		return "", errors.Wrap(err, "failed to create contract caller")
    76  	}
    77  
    78  	value := new(contracts.ProjectDeviceApprove)
    79  	result := NewContractResult(&projectDeviceABI, eventOnApprove, value)
    80  	if _, err = caller.CallAndRetrieveResult(funcDevicesApprove, []any{
    81  		big.NewInt(int64(projectID)),
    82  		deviceAddress,
    83  	}, result); err != nil {
    84  		return "", errors.Wrap(err, "failed to read contract")
    85  	}
    86  	if _, err = result.Result(); err != nil {
    87  		return "", err
    88  	}
    89  
    90  	return fmt.Sprintf("approve %d device", len(deviceAddress)), nil
    91  }
```


A very standard case of error



## o. (false positive: false) https://go-mod-viewer.appspot.com/github.com/kamva/gutil@v0.0.0-20220525102242-64de879b3b0e/reflection.go#L101


```go
    89  // StructTags return struct all fields tags.
    90  func StructTags(val interface{}) ([]reflect.StructTag, error) {
    91  	rType, err := IndirectType(val)
    92  
    93  	if err != nil {
    94  		return nil, err
    95  	}
    96  
    97  	if rType.Kind() != reflect.Struct {
    98  		return nil, errors.New("value must be a struct or pointer to struct")
    99  	}
   100  
   101  	tags := make([]reflect.StructTag, rType.NumField())
   102  	for i := 0; i < rType.NumField(); i++ {
   103  		tags = append(tags, rType.Field(i).Tag)
   104  	}
   105  
   106  	return tags, nil
   107  }
```


A very standard case of error


## p. (false positive: false) https://go-mod-viewer.appspot.com/github.com/klaytn/klaytn@v1.12.1/console/console.go#L282


```go
279  // consoleOutput is an override for the console.log and console.error methods to
   280  // stream the output into the configured output stream instead of stdout.
   281  func (c *Console) consoleOutput(call goja.FunctionCall) goja.Value {
   282  	output := make([]string, len(call.Arguments))
   283  	for _, argument := range call.Arguments {
   284  		output = append(output, fmt.Sprintf("%v", argument))
   285  	}
   286  	fmt.Fprintln(c.printer, strings.Join(output, " "))
   287  	return goja.Null()
   288  }

```


A very standard case of error


## q. (false positive: true) https://go-mod-viewer.appspot.com/github.com/krotik/common@v1.5.1/datautil/userdb.go#L179


```go
  158  /*
   159  UpdateUserPassword updates the password of a user entry.
   160  */
   161  func (ud *UserDB) UpdateUserPassword(name, password string) error {
   162  	var err error
   163  
   164  	if ud.CheckUserPassword(name, password) {
   165  		return fmt.Errorf("Cannot reuse current password")
   166  	}
   167  
   168  	ud.DataLock.Lock()
   169  	defer ud.DataLock.Unlock()
   170  
   171  	e, ok := ud.Data[name]
   172  
   173  	if !ok {
   174  		return fmt.Errorf("Unknown user %v", name)
   175  	}
   176  
   177  	// Generate a new salt and passhash for the user
   178  
   179  	salt := make([]byte, sha256.Size)
   180  
   181  	if _, err = io.ReadFull(rand.Reader, salt); err == nil {
   182  		passhash := sha256.Sum256(append(salt, []byte(password)...))
   183  
   184  		// Store old hash in the history
   185  
   186  		if len(e.PasshashHistory) < MaxPassHistory {
   187  			e.PasshashHistory = append(e.PasshashHistory, e.Passhash)
   188  			e.SaltHistory = append(e.SaltHistory, e.Salt)
   189  		} else {
   190  			e.PasshashHistory = append(e.PasshashHistory[1:], e.Passhash)
   191  			e.SaltHistory = append(e.SaltHistory[1:], e.Salt)
   192  		}
   193  
   194  		// Store the new hash
   195  
   196  		e.Passhash = string((&passhash)[:])
   197  		e.Salt = salt
   198  
   199  		err = ud.flush()
   200  	}
   201  
   202  	return err
   203  }
```



`rand.Reader` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it






## r. (false positive: false) https://go-mod-viewer.appspot.com/github.com/ledgerwatch/erigon-lib@v1.0.0/downloader/downloader.go#L683


```go
   682  func (d *WebSeeds) Discover(ctx context.Context, urls []*url.URL, files []string) {
   683  	list := make([]snaptype.WebSeedsFromProvider, len(urls)+len(files))
   684  	for _, webSeedProviderURL := range urls {
   685  		select {
   686  		case <-ctx.Done():
   687  			break
   688  		default:
   689  		}
   690  		response, err := d.callWebSeedsProvider(ctx, webSeedProviderURL)
   691  		if err != nil { // don't fail on error
   692  			log.Warn("[downloader] callWebSeedsProvider", "err", err, "url", webSeedProviderURL.EscapedPath())
   693  			continue
   694  		}
   695  		list = append(list, response)
   696  	}
   697  	for _, webSeedFile := range files {
   698  		response, err := d.readWebSeedsFile(webSeedFile)
   699  		if err != nil { // don't fail on error
   700  			_, fileName := filepath.Split(webSeedFile)
   701  			log.Warn("[downloader] readWebSeedsFile", "err", err, "file", fileName)
   702  			continue
   703  		}
   704  		list = append(list, response)
   705  	}
   706  	d.SetByFileNames(snaptype.NewWebSeeds(list))
   707  }
```

A very standard case of error



## s. (false positive: false) https://go-mod-viewer.appspot.com/github.com/lomik/graphite-clickhouse@v0.14.0/config/config.go#L688

```go
   686  	checkDeprecations(cfg, deprecations)
   687  	if len(deprecations) != 0 {
   688  		deprecationList := make([]error, len(deprecations))
   689  		for name, message := range deprecations {
   690  			deprecationList = append(deprecationList, errors.Wrap(message, name))
   691  		}
   692  		warns = append(warns, zap.Errors("config deprecations", deprecationList))
   693  	}
```

A very standard case of error



## t. (false positive: true) https://go-mod-viewer.appspot.com/github.com/mavryk-network/mvgo@v1.19.9/mavryk/crypto.go#L177


```go
   165  func encryptPrivateKey(key []byte, fn PassphraseFunc) ([]byte, error) {
   166  	if fn == nil {
   167  		return nil, ErrPassphrase
   168  	}
   169  	passphrase, err := fn()
   170  	if err != nil {
   171  		return nil, err
   172  	}
   173  	if len(passphrase) == 0 {
   174  		return nil, ErrPassphrase
   175  	}
   176  
   177  	salt := make([]byte, 8)
   178  	_, err = rand.Read(salt)
   179  	if err != nil {
   180  		return nil, err
   181  	}
   182  	secretboxKey := pbkdf2.Key(passphrase, salt, encIterations, encKeyLen, sha512.New)
   183  
   184  	var (
   185  		tmp   [32]byte
   186  		nonce [24]byte // implicitly 0x00..
   187  	)
   188  	copy(tmp[:], secretboxKey)
   189  	enc := secretbox.Seal(nil, key, &nonce, &tmp)
   190  	return append(salt, enc...), nil
   191  }
```




`rand.Read` should be the same as `binary.LittleEndian.PutUint16`, ignoring detection if the slice is called by it
