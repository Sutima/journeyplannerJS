package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall/js"
	"time"

	"gonum.org/v1/gonum/graph/path"
	"gonum.org/v1/gonum/graph/simple"
)

type System struct {
	Name     string `json:"name"`
	Security string `json:"security"`
	Class    string `json:"class"`
}

type MapStruct struct {
	Shortest map[string]map[string]int `json:"shortest"`
}

type WormholeRef struct {
	Jump int64 `json:"jump"`
}

type DataRef struct {
	Systems   map[string]System      `json:"systems"`
	Map       MapStruct              `json:"map"`
	Wormholes map[string]WormholeRef `json:"wormholes"`
}

type Wormhole struct {
	Life        string `json:"life"`
	Mass        string `json:"mass"`
	Type        string `json:"type"`
	InitialID   string `json:"initialID"`
	SecondaryID string `json:"secondaryID"`
}

type Signature struct {
	SignatureID string `json:"signatureID"`
	SystemID    string `json:"systemID"`
	LifeTime    string `json:"lifeTime"`
}

type DataWh struct {
	Wormholes map[string]Wormhole  `json:"wormholes"`
	Signature map[string]Signature `json:"signatures"`
}

type TheraWormhole struct {
	OutSystemId    int64  `json:"out_system_id"`
	OutSignature   string `json:"out_signature"`
	InSystemId     int64  `json:"in_system_id"`
	InSignature    string `json:"in_signature"`
	RemainingHours int64  `json:"remaining_hours"`
}

type Node struct {
	Name     string  `json:"name"`
	Security float64 `json:"security"`
	Class    string  `json:"class"`
	SystemId int64   `json:"systemid"`
}

type EdgeKey struct {
	Src int64
	Dst int64
}

type Edge struct {
	Signature  string `json:"signature"`
	JumpMass   int64  `json:"jumpmass"`
	LifeStatus string `json:"lifestatus"`
	MassStatus string `json:"massstatus"`
}

type FullGraph struct {
	Graph      *simple.DirectedGraph
	Nodes      map[int64]Node
	Edges      map[EdgeKey]Edge
	NodeLookup map[string]int64
}

type PathEntry struct {
	Node Node `json:"node"`
	Edge Edge `json:"edge"`
}

type SystemEntry struct {
	ID   int64  `json:"id"`
	Text string `json:"text"`
}

type Options struct {
	FromSystem     SystemEntry   `json:"fromsystem"`
	ToSystem       SystemEntry   `json:"tosystem"`
	AvoidSystems   []SystemEntry `json:"avoidsystems"`
	ShipSize       int64         `json:"shipsize"`
	ExcludeVOC     bool          `json:"excludevoc"`
	ExcludeEOL     bool          `json:"excludeeol"`
	ExcludeLowSec  bool          `json:"excludelowsec"`
	ExcludeNullSec bool          `json:"excludenullsec"`
}

func NewFullGraph() *FullGraph {
	fullgraph := &FullGraph{simple.NewDirectedGraph(), make(map[int64]Node), make(map[EdgeKey]Edge), make(map[string]int64)}
	return fullgraph
}

func CopyFullGraph(original *FullGraph) *FullGraph {
	fullgraph := &FullGraph{simple.NewDirectedGraph(), original.Nodes, original.Edges, original.NodeLookup}
	for systemId := range original.Nodes {
		fullgraph.Graph.AddNode(simple.Node(systemId))
	}
	for edgeKey := range original.Edges {
		fullgraph.Graph.SetEdge(simple.Edge{F: simple.Node(edgeKey.Src), T: simple.Node(edgeKey.Dst)})
	}
	return fullgraph
}

func HttpRequest(client *http.Client, method string, url string, data url.Values) ([]byte, error) {
	var body io.Reader = nil
	if method == http.MethodPost {
		body = strings.NewReader(data.Encode())
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if res.Body != nil {
		defer res.Body.Close()
	}
	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func RefreshGraph() (*FullGraph, error) {
	fullgraph := NewFullGraph()

	client := &http.Client{
		Timeout: time.Second * 60,
	}

	/***********************
	Download reference data
	************************/

	bytes, err := HttpRequest(client, http.MethodGet, "/js/combine.js", nil)
	if err != nil {
		return nil, errors.New("Failed to download the reference data - " + err.Error())
	}

	bytes = bytes[14:]

	var dataRef DataRef

	err = json.Unmarshal(bytes, &dataRef)
	if err != nil {
		return nil, errors.New("Failed to parse the reference data - " + err.Error())
	}

	/**********
	 Add Nodes
	***********/

	for systemIdString, system := range dataRef.Systems {
		systemId, err := strconv.ParseInt(systemIdString, 10, 64)
		if err != nil {
			continue
		}

		security, err := strconv.ParseFloat(system.Security, 64)
		if err != nil {
			continue
		}

		fullgraph.Graph.AddNode(simple.Node(systemId))
		fullgraph.Nodes[systemId] = Node{system.Name, security, system.Class, systemId}
		fullgraph.NodeLookup[system.Name] = systemId
	}

	/******************
	 Add k-space Edges
	*******************/

	for fromSystemIdString, toSystemIdMap := range dataRef.Map.Shortest {
		fromSystemId, err := strconv.ParseInt(fromSystemIdString, 10, 64)
		if err != nil {
			continue
		}
		fromSystemId += 30000000
		for toSystemIdString, _ := range toSystemIdMap {
			toSystemId, err := strconv.ParseInt(toSystemIdString, 10, 64)
			if err != nil {
				continue
			}
			toSystemId += 30000000
			fullgraph.Graph.SetEdge(simple.Edge{F: simple.Node(fromSystemId), T: simple.Node(toSystemId)})
			fullgraph.Edges[EdgeKey{fromSystemId, toSystemId}] = Edge{"", 9999, "stable", "stable"}
		}
	}

	/********************************
	 Download Tripwire wormhole data
	*********************************/

	bytes, err = HttpRequest(client, http.MethodPost, "/refresh.php", url.Values{
		"mode":       {"init"},
		"systemID":   {"30000142"},
		"systemName": {"Jita"},
	})
	if err != nil {
		return nil, errors.New("Failed to download the current tripwire map - " + err.Error())
	}

	var dataWh DataWh
	err = json.Unmarshal(bytes, &dataWh)
	if err != nil {
		return nil, errors.New("Failed to parse the current tripwire map - " + err.Error())
	}

	/***************************
	 Add j-space Tripwire Edges
	****************************/

	for _, wormhole := range dataWh.Wormholes {
		fromSignatureData, ok := dataWh.Signature[wormhole.InitialID]
		if !ok {
			continue
		}

		toSignatureData, ok := dataWh.Signature[wormhole.SecondaryID]
		if !ok {
			continue
		}

		fromSignature := fromSignatureData.SignatureID
		toSignature := toSignatureData.SignatureID

		if fromSignature == "" {
			fromSignature = "???"
		}

		if toSignature == "" {
			toSignature = "???"
		}

		fromSignature = strings.ToUpper(fromSignature[:3])
		toSignature = strings.ToUpper(toSignature[:3])

		// If we don't know the sig on either side, someone deathcloned and auto-created a fake wormhole
		if fromSignature == "???" && toSignature == "???" {
			continue
		}

		if _, ok := dataRef.Systems[fromSignatureData.SystemID]; !ok {
			continue
		}

		if _, ok := dataRef.Systems[toSignatureData.SystemID]; !ok {
			continue
		}

		fromSystemId, err := strconv.ParseInt(fromSignatureData.SystemID, 10, 64)
		if err != nil {
			continue
		}

		toSystemId, err := strconv.ParseInt(toSignatureData.SystemID, 10, 64)
		if err != nil {
			continue
		}

		if wormhole.Type == "" {
			wormhole.Type = "????"
		}

		var jumpMass int64 = 9999
		if wormhole.Type == "SML" {
			jumpMass = 5
		} else if wormhole.Type == "MED" {
			jumpMass = 62
		} else {
			wormholeRef, ok := dataRef.Wormholes[wormhole.Type]
			if ok {
				jumpMass = wormholeRef.Jump / 1000000
			}
		}

		lifeStatus := wormhole.Life

		lifeTime, err := time.Parse("2006-01-02 15:04:05", fromSignatureData.LifeTime)
		if err == nil {
			lifeTimeSince := time.Since(lifeTime).Hours()

			// it is very rare for a wormhole to last >24 hours
			if lifeTimeSince > 24.0 {
				continue
			}

			if lifeTimeSince > 20.0 {
				lifeStatus = "critical"
			}
		}

		fullgraph.Graph.SetEdge(simple.Edge{F: simple.Node(fromSystemId), T: simple.Node(toSystemId)})
		fullgraph.Edges[EdgeKey{fromSystemId, toSystemId}] = Edge{fromSignature, jumpMass, lifeStatus, wormhole.Mass}
		fullgraph.Edges[EdgeKey{toSystemId, fromSystemId}] = Edge{toSignature, jumpMass, lifeStatus, wormhole.Mass}

	}

	/***************************************
	 Download Eve-Scout Thera wormhole data
	****************************************/

	bytes, err = HttpRequest(client, http.MethodGet, "https://corsproxy.io/?"+url.QueryEscape("https://api.eve-scout.com/v2/public/signatures"), nil)
	if err != nil {
		return nil, errors.New("Failed to download the eve-scout data - " + err.Error())
	}

	var dataThera []TheraWormhole

	err = json.Unmarshal(bytes, &dataThera)
	if err != nil {
		return nil, errors.New("Failed to parse the eve-scout data - " + err.Error())
	}

	/****************
	 Add Thera Edges
	****************/

	for _, theraWormhole := range dataThera {
		fromSignature := theraWormhole.InSignature[:3]
		toSignature := theraWormhole.OutSignature[:3]
		fromSystemId := theraWormhole.InSystemId
		toSystemId := theraWormhole.OutSystemId

		eol := "stable"
		if theraWormhole.RemainingHours <= 4 {
			eol = "critical"
		}

		fullgraph.Graph.SetEdge(simple.Edge{F: simple.Node(fromSystemId), T: simple.Node(toSystemId)})
		fullgraph.Edges[EdgeKey{fromSystemId, toSystemId}] = Edge{fromSignature, 9999, eol, "stable"}
		fullgraph.Edges[EdgeKey{toSystemId, fromSystemId}] = Edge{toSignature, 9999, eol, "stable"}
	}

	/*********
	 Clean up
	**********/

	for edgeKey, edge := range fullgraph.Edges {
		nodeSrc, ok := fullgraph.Nodes[edgeKey.Src]
		if !ok {
			continue
		}

		nodeDst, ok := fullgraph.Nodes[edgeKey.Dst]
		if !ok {
			continue
		}

		if edge.JumpMass == 9999 {
			if nodeSrc.Class == "1" || nodeDst.Class == "1" {
				edge.JumpMass = 62
			} else if (nodeSrc.Class == "5" || nodeSrc.Class == "6") && (nodeDst.Class == "5" || nodeDst.Class == "6") {
				edge.JumpMass = 2000
			} else if nodeSrc.Class == "2" || nodeSrc.Class == "3" || nodeSrc.Class == "4" || nodeDst.Class == "2" || nodeDst.Class == "3" || nodeDst.Class == "4" {
				edge.JumpMass = 375
			} else {
				edge.JumpMass = 2000 // might not be correct for low-sec / null-sec
			}

			fullgraph.Edges[edgeKey] = edge
		}
	}

	for systemId, node := range fullgraph.Nodes {
		if node.Name == "Thera" {
			node.Class = "99"
			fullgraph.Nodes[systemId] = node
		}
	}

	return fullgraph, nil
}

func ShortestPath(original *FullGraph, options Options) ([]PathEntry, error) {
	fullgraph := CopyFullGraph(original)

	/**********
	 Filter
	***********/

	for edgeKey, edge := range fullgraph.Edges {
		if (options.ShipSize > edge.JumpMass) || (edge.LifeStatus == "critical" && options.ExcludeEOL) || (edge.MassStatus == "critical" && options.ExcludeVOC) {
			fullgraph.Graph.RemoveEdge(edgeKey.Src, edgeKey.Dst)
		}
	}

	for systemId, node := range fullgraph.Nodes {
		if node.Class == "" && ((node.Security < 0.45 && node.Security > 0.0 && options.ExcludeLowSec) || (node.Security <= 0.0 && options.ExcludeNullSec)) {
			fullgraph.Graph.RemoveNode(systemId)
		}
	}

	for _, avoidSystem := range options.AvoidSystems {
		fullgraph.Graph.RemoveNode(avoidSystem.ID)
	}

	/**************
	 Shortest Path
	***************/

	result := make([]PathEntry, 0)

	pth := path.DijkstraFrom(simple.Node(options.FromSystem.ID), fullgraph.Graph)
	pthNodes, _ := pth.To(options.ToSystem.ID)
	for i := 1; i < len(pthNodes); i++ {
		pthNode, ok := fullgraph.Nodes[pthNodes[i].ID()]
		if !ok {
			return nil, errors.New("Can't find a node")
		}
		pthEdge, ok := fullgraph.Edges[EdgeKey{pthNodes[i-1].ID(), pthNodes[i].ID()}]
		if !ok {
			return nil, errors.New("Can't find an edge")
		}
		result = append(result, PathEntry{pthNode, pthEdge})
	}

	return result, nil
}

func main() {
	var fullgraph *FullGraph = nil
	var systems []SystemEntry = nil

	func_refresh := js.FuncOf(func(this js.Value, args []js.Value) any {
		handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			resolve := args[0]
			reject := args[1]

			go func() {
				var err error = nil
				var newfullgraph *FullGraph
				var newsystems []SystemEntry

				if err == nil {
					newfullgraph, err = RefreshGraph()
				}

				if err == nil {
					newsystems = make([]SystemEntry, 0, 500)
					for systemId, node := range newfullgraph.Nodes {
						newsystems = append(newsystems, SystemEntry{systemId, node.Name})
					}
				}

				if err == nil {
					fullgraph = newfullgraph
					systems = newsystems
				}

				if err == nil {
					resolve.Invoke("Done!")
				} else {
					errorConstructor := js.Global().Get("Error")
					errorObject := errorConstructor.New(err.Error())
					reject.Invoke(errorObject)
				}
			}()

			return nil
		})

		promiseConstructor := js.Global().Get("Promise")
		return promiseConstructor.New(handler)
	})

	func_systems := js.FuncOf(func(this js.Value, args []js.Value) any {
		handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			resolve := args[0]
			reject := args[1]

			go func() {
				var err error = nil
				var builder *strings.Builder

				if err == nil {
					builder = new(strings.Builder)
					err = json.NewEncoder(builder).Encode(systems)
				}

				if err == nil {
					resolve.Invoke(builder.String())
				} else {
					errorConstructor := js.Global().Get("Error")
					errorObject := errorConstructor.New(err.Error())
					reject.Invoke(errorObject)
				}
			}()

			return nil
		})

		promiseConstructor := js.Global().Get("Promise")
		return promiseConstructor.New(handler)
	})

	func_navigate := js.FuncOf(func(this js.Value, args []js.Value) any {
		rawoptions := args[0].String()

		handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			resolve := args[0]
			reject := args[1]

			go func() {
				var err error = nil
				var options Options
				var path []PathEntry
				var reader *strings.Reader
				var builder *strings.Builder

				if err == nil {
					reader = strings.NewReader(rawoptions)
					err = json.NewDecoder(reader).Decode(&options)
				}

				if err == nil {
					path, err = ShortestPath(fullgraph, options)
				}

				if err == nil {
					builder = new(strings.Builder)
					err = json.NewEncoder(builder).Encode(path)
				}

				if err == nil {
					resolve.Invoke(builder.String())
				} else {
					errorConstructor := js.Global().Get("Error")
					errorObject := errorConstructor.New(err.Error())
					reject.Invoke(errorObject)
				}
			}()

			return nil
		})

		promiseConstructor := js.Global().Get("Promise")
		return promiseConstructor.New(handler)
	})

	js.Global().Set("go_systems", func_systems)
	js.Global().Set("go_navigate", func_navigate)
	js.Global().Set("go_refresh", func_refresh)
	js.Global().Call("startup")

	// Never return (required for WASM)
	done := make(chan struct{}, 0)
	<-done
}
