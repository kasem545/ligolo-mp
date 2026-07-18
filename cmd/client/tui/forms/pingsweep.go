package forms

import (
	"github.com/rivo/tview"
)

var (
	pingsweep_cidr = FormVal[string]{
		Hint: "CIDR range to sweep on the agent's local network (max /24)\n\nExample:\n192.168.1.0/24",
	}
)

type PingSweepForm struct {
	tview.Flex
	form      *tview.Form
	submitBtn *tview.Button
	cancelBtn *tview.Button
}

func NewPingSweepForm() *PingSweepForm {
	page := &PingSweepForm{
		Flex:      *tview.NewFlex(),
		form:      tview.NewForm(),
		submitBtn: tview.NewButton("Submit"),
		cancelBtn: tview.NewButton("Cancel"),
	}

	hintBox := tview.NewTextView()
	hintBox.SetTitle("HINT")
	hintBox.SetTitleAlign(tview.AlignCenter)
	hintBox.SetBorder(true)
	hintBox.SetBorderPadding(1, 1, 1, 1)

	page.form.SetTitle("Ping sweep").SetTitleAlign(tview.AlignCenter)
	page.form.SetBorder(true)
	page.form.SetButtonsAlign(tview.AlignCenter)

	cidrField := tview.NewInputField()
	cidrField.SetLabel("CIDR")
	cidrField.SetText(pingsweep_cidr.Last)
	cidrField.SetFocusFunc(func() {
		hintBox.SetText(pingsweep_cidr.Hint)
	})
	cidrField.SetChangedFunc(func(text string) {
		pingsweep_cidr.Last = text
	})
	page.form.AddFormItem(cidrField)

	page.form.AddButton("Submit", nil)
	page.form.AddButton("Cancel", nil)

	formFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(page.form, 11, 1, true).
		AddItem(hintBox, 8, 1, false)

	page.Flex.AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(formFlex, 0, 1, true).
			AddItem(nil, 0, 1, false),
			0, 1, true).
		AddItem(nil, 0, 1, false)

	return page
}

func (page *PingSweepForm) GetID() string {
	return "pingsweep_page"
}

func (page *PingSweepForm) SetSubmitFunc(f func(string)) {
	btnId := page.form.GetButtonIndex("Submit")
	submitBtn := page.form.GetButton(btnId)
	submitBtn.SetSelectedFunc(func() {
		f(pingsweep_cidr.Last)
	})
}

func (page *PingSweepForm) SetCancelFunc(f func()) {
	btnId := page.form.GetButtonIndex("Cancel")
	submitBtn := page.form.GetButton(btnId)
	submitBtn.SetSelectedFunc(f)
}
